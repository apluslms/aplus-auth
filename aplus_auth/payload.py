from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple, Union


class Permission(int):
    """
    Different permissions. To get multiple permissions, use multiple PermissionItems.
    """
    NONE: Permission = 0 # type: ignore
    READ: Permission = 1 # type: ignore
    WRITE: Permission = 2 # type: ignore
    CREATE: Permission = 4 # type: ignore


# (permission, details)
PermissionItem = Tuple[Permission, Dict[str, Any]]
# (permission_type, permission, details)
PermissionSpec = Tuple[str, Permission, Dict[str, Any]]


class PermissionItemList:
    """
    List of permissions for a single type.
    """
    def __init__(self, type: str, items: Optional[List[PermissionItem]] = None) -> None:
        if items is None:
            items = []
        self.type = type
        self.items: List[PermissionItem] = items

    def __iter__(self) -> Iterator[PermissionSpec]:
        return ((self.type, *i) for i in self.items)

    def add(self, p: Permission, **kwargs: Any) -> None:
        self.items.append((p, kwargs))

    def remove(self, permission: Optional[Permission] = None, **kwargs: Any) -> None:
        matches = list(self.gets(permission, **kwargs))
        self.items = [i for i in self.items if i not in matches]

    def gets(self, permission: Optional[Permission] = None, **kwargs: Any) -> Generator[PermissionItem, None, None]:
        for value in self.items:
            if permission is None or permission == value[0]:
                for k, v in kwargs.items():
                    if k not in value[1] or value[1][k] != v:
                        break
                else:
                    yield value

    def get(self,
            permission: Optional[Permission] = None,
            raise_if_multiple: bool = False,
            **kwargs: Any,
            ) -> Union[Tuple[None, None], PermissionItem]:
        g = self.gets(permission, **kwargs)
        v = next(g, (None, None))
        if raise_if_multiple and next(g, None) is not None:
            raise KeyError("Multiple permissions match given conditions")

        return v

    def has(self, permission: Optional[Permission] = None, **kwargs: Any) -> bool:
        return self.get(permission, **kwargs)[0] is not None

    def __contains__(self, item: Tuple[Permission, Dict[str,Any]]) -> bool:
        return self.has(item[0], **item[1])


class Permissions:
    """
    Constructs and holds an PermissionItemList for each type.
    """
    def __init__(self, permissions: Optional[List[PermissionSpec]] = None):
        if permissions is None:
            permissions = []

        perms: Dict[str, List[Tuple[Permission, Dict[str, Any]]]] = {}
        for k, permission, detail in permissions:
            perms.setdefault(k, [])
            perms[k].append((permission, detail))

        for k in perms.keys():
            if k not in ("course", "instance", "module", "exercise", "submission"):
                raise ValueError(f"Unknown permission type: {k}")

        self.courses = PermissionItemList("course", perms.get("course", []))
        self.instances = PermissionItemList("instance", perms.get("instance", []))
        self.modules = PermissionItemList("module", perms.get("module", []))
        self.exercises = PermissionItemList("exercise", perms.get("exercise", []))
        self.submissions = PermissionItemList("submission", perms.get("submission", []))

    def __iter__(self) -> Iterator[PermissionSpec]:
        yield from self.courses
        yield from self.instances
        yield from self.modules
        yield from self.exercises
        yield from self.submissions

    def get_list(self, type: str) -> PermissionItemList:
        return getattr(self, type)

    def add(self, type: str, p: Permission, **kwargs: Any) -> None:
        self.get_list(type).add(p, **kwargs)

    def remove(self, type: str, permission: Optional[Permission] = None, **kwargs: Any) -> None:
        self.get_list(type).remove(permission, **kwargs)

    def has(self, type: str, permission: Optional[Permission] = None, **kwargs: Any) -> bool:
        return self.get_list(type).has(permission, **kwargs)

    def gets(self,
            type: str,
            permission: Optional[Permission] = None,
            **kwargs: Any,
            ) -> Generator[PermissionItem, None, None]:
        return self.get_list(type).gets(permission, **kwargs)

    def get(self,
            type: str,
            permission: Optional[Permission] = None,
            **kwargs: Any,
            ) -> Union[Tuple[None, None], PermissionItem]:
        return self.get_list(type).get(permission, **kwargs)


class Payload:
    """
    Payload for a JWT.

    - iss: issuer, the signer of the token
    - sub: subject, the sender of the token
    - aud: audience, the receiver of the token
    - exp: expiration time
    - tokens: list of special access tokens, e.g. submission grading token
    - extra (kwargs): additional fields that are not necessarily validated

    Do NOT put any of the above fields inside the extra dict.
    """
    iss: Optional[str]
    sub: Optional[str]
    aud: Optional[str]
    exp: Optional[Union[datetime, timedelta]]
    permissions: Permissions
    tokens: Optional[List[str]]
    extra: Dict[str, Any]

    def __init__(self,
            iss: Optional[str] = None,
            sub: Optional[str] = None,
            aud: Optional[str] = None,
            exp: Optional[Union[timedelta, datetime, float]] = None,
            permissions: Union[Permissions, List[PermissionSpec]] = Permissions(),
            tokens: Optional[List[str]] = None,
            **kwargs: Any,
            ) -> None:

        self.iss = iss
        self.sub = sub
        self.aud = aud
        if isinstance(exp, timedelta) or isinstance(exp, datetime):
            self.exp = exp
        elif isinstance(exp, float):
            self.exp = datetime.utcfromtimestamp(exp)
        elif isinstance(exp, str):
            try:
                time = datetime.strptime(exp, "%H:%M:%S")
                self.exp = timedelta(hours=time.hour, minutes=time.minute, seconds=time.second)
            except:
                self.exp = datetime.fromisoformat(exp)
        else:
            self.exp = None

        if isinstance(permissions, Permissions):
            self.permissions = permissions
        else:
            self.permissions = Permissions(permissions)

        self.tokens = tokens
        self.extra = kwargs

    def __bool__(self) -> bool:
        return (
            self.iss is not None
            or self.sub is not None
            or self.aud is not None
            or self.exp is not None
            or self.tokens is not None
            or next(iter(self.permissions), None) is not None
            or bool(self.extra)
        )

    def __contains__(self, item: str) -> bool:
        return self.get(item, None) is not None

    def get(self, item: str, default: Any = None) -> None:
        o = getattr(self, item)
        if o is not None:
            return o
        return default

    def to_dict(self) -> Dict[str, Any]:
        out = deepcopy(self.extra)
        if self.iss is not None:
            out["iss"] = self.iss
        if self.sub is not None:
            out["sub"] = self.sub
        if self.aud is not None:
            out["aud"] = self.aud
        if isinstance(self.exp, timedelta):
            out["exp"] = datetime.utcnow() + self.exp
        elif self.exp is not None:
            out["exp"] = self.exp
        if self.tokens is not None:
            out["tokens"] = self.tokens
        out["permissions"] = list(self.permissions)
        return out
