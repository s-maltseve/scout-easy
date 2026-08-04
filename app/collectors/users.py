from __future__ import annotations

import grp
import os
import pwd

_ADMIN_GROUPS = {"sudo", "wheel", "admin", "root"}


def collect_users() -> dict:
    groups_by_user: dict[str, set[str]] = {}
    all_groups: list[dict] = []
    for group in grp.getgrall():
        all_groups.append({"name": group.gr_name, "gid": group.gr_gid, "members": list(group.gr_mem)})
        for member in group.gr_mem:
            groups_by_user.setdefault(member, set()).add(group.gr_name)

    users: list[dict] = []
    for entry in pwd.getpwall():
        try:
            primary = grp.getgrgid(entry.pw_gid).gr_name
        except KeyError:
            primary = str(entry.pw_gid)
        groups = {primary, *groups_by_user.get(entry.pw_name, set())}
        shell = entry.pw_shell or ""
        login_allowed = shell not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}
        admin = entry.pw_uid == 0 or bool(groups & _ADMIN_GROUPS)
        users.append({
            "username": entry.pw_name,
            "uid": entry.pw_uid,
            "gid": entry.pw_gid,
            "gecos": entry.pw_gecos,
            "home": entry.pw_dir,
            "shell": shell,
            "groups": sorted(groups),
            "primary_group": primary,
            "is_admin": admin,
            "is_system": entry.pw_uid < 1000 and entry.pw_uid != 0,
            "login_allowed": login_allowed,
            "home_exists": os.path.isdir(entry.pw_dir),
        })
    users.sort(key=lambda item: (item["is_system"], item["uid"], item["username"]))
    all_groups.sort(key=lambda item: item["gid"])
    return {"users": users, "groups": all_groups}
