from __future__ import annotations

import grp
import os
import pwd

_ADMIN_GROUPS = {"sudo", "wheel", "admin", "root"}
_SERVICE_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}
_SPECIAL_SYSTEM_USERS = {"sync", "shutdown", "halt", "nobody"}


def collect_users() -> dict:
    groups_by_user: dict[str, set[str]] = {}
    all_groups: list[dict] = []
    for group in grp.getgrall():
        all_groups.append({"name": group.gr_name, "gid": group.gr_gid, "members": list(group.gr_mem)})
        for member in group.gr_mem:
            groups_by_user.setdefault(member, set()).add(group.gr_name)

    users: list[dict] = []
    counters = {"total": 0, "human": 0, "system": 0, "admin": 0, "interactive": 0, "service": 0}
    for entry in pwd.getpwall():
        try:
            primary = grp.getgrgid(entry.pw_gid).gr_name
        except KeyError:
            primary = str(entry.pw_gid)
        groups = {primary, *groups_by_user.get(entry.pw_name, set())}
        shell = entry.pw_shell or ""
        login_allowed = shell not in _SERVICE_SHELLS
        admin = entry.pw_uid == 0 or bool(groups & _ADMIN_GROUPS)
        is_system = entry.pw_uid < 1000 and entry.pw_uid != 0
        is_service = is_system and (not login_allowed or entry.pw_name in _SPECIAL_SYSTEM_USERS)
        is_human = entry.pw_uid >= 1000 and entry.pw_uid < 65534
        tags: list[str] = []
        if admin: tags.append("администратор")
        if is_human: tags.append("создана пользователем")
        elif is_service: tags.append("служебная")
        elif is_system: tags.append("системная")
        else: tags.append("специальная")
        if login_allowed and entry.pw_name not in _SPECIAL_SYSTEM_USERS: tags.append("интерактивная")
        else: tags.append("вход запрещён")
        if groups & {"docker", "lxd", "shadow", "adm"}: tags.append("повышенные права")
        counters["total"] += 1
        counters["admin"] += int(admin)
        counters["human"] += int(is_human)
        counters["system"] += int(is_system)
        counters["service"] += int(is_service)
        counters["interactive"] += int(login_allowed and entry.pw_name not in _SPECIAL_SYSTEM_USERS)
        users.append({
            "username": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid,
            "gecos": entry.pw_gecos, "home": entry.pw_dir, "shell": shell,
            "groups": sorted(groups), "primary_group": primary, "is_admin": admin,
            "is_system": is_system, "is_service": is_service, "is_human": is_human,
            "login_allowed": login_allowed and entry.pw_name not in _SPECIAL_SYSTEM_USERS,
            "home_exists": os.path.isdir(entry.pw_dir), "tags": tags,
        })
    users.sort(key=lambda item: (not item["is_admin"], not item["is_human"], item["is_system"], item["uid"], item["username"]))
    all_groups.sort(key=lambda item: item["gid"])
    return {"users": users, "groups": all_groups, "summary": counters}
