from universal_email_mcp.mail.folders import RawFolder, assign_roles, decode_folder_name


def folders(*specs: tuple[str, tuple[str, ...]], delim: str = ".") -> list[RawFolder]:
    return [RawFolder(n, decode_folder_name(n), delim, flags) for n, flags in specs]


def test_decode_folder_name():
    assert decode_folder_name("INBOX") == "INBOX"
    assert decode_folder_name("Entw&APw-rfe") == "Entwürfe"
    assert decode_folder_name("Gel&APY-schte Elemente") == "Gelöschte Elemente"
    assert decode_folder_name("&-") == "&"
    assert decode_folder_name("bad&ZZZ") in ("bad&ZZZ", decode_folder_name("bad&ZZZ"))


def test_special_use_wins_over_names():
    roles, warnings = assign_roles(
        folders(
            ("INBOX", ()),
            ("Sent", ()),
            ("Postausgang-Kopie", ("\\Sent",)),
            ("Trash", ("\\Trash",)),
        )
    )
    assert roles == {"INBOX": "inbox", "Postausgang-Kopie": "sent", "Trash": "trash"}
    assert warnings == []


def test_german_heuristics_under_inbox():
    roles, _ = assign_roles(
        folders(
            ("INBOX", ()),
            ("INBOX.Gesendete Objekte", ()),
            ("INBOX.Entw&APw-rfe", ()),
            ("INBOX.Papierkorb", ()),
            ("INBOX.Spam", ()),
            ("INBOX.Archiv", ()),
        )
    )
    assert roles == {
        "INBOX": "inbox",
        "INBOX.Gesendete Objekte": "sent",
        "INBOX.Entw&APw-rfe": "drafts",
        "INBOX.Papierkorb": "trash",
        "INBOX.Spam": "junk",
        "INBOX.Archiv": "archive",
    }


def test_english_exchange_names_and_preference():
    roles, _ = assign_roles(
        folders(
            ("INBOX", ()),
            ("Sent Items", ()),
            ("Sent", ()),
            ("Deleted Items", ()),
            ("Junk E-Mail", ()),
            delim="/",
        )
    )
    assert roles["Sent"] == "sent"  # "sent" ranks before "sent items"
    assert roles["Deleted Items"] == "trash"
    assert roles["Junk E-Mail"] == "junk"
    assert "Sent Items" not in roles


def test_nested_user_folders_are_not_roles():
    roles, _ = assign_roles(
        folders(("INBOX", ()), ("Projects/Archive", ()), ("Projects/Sent", ()), delim="/")
    )
    assert roles == {"INBOX": "inbox"}


def test_noselect_is_ignored_and_case_insensitive_inbox():
    roles, _ = assign_roles(folders(("inbox", ()), ("Trash", ("\\Noselect",))))
    assert roles == {"inbox": "inbox"}


def test_overrides_take_precedence_and_warn():
    roles, warnings = assign_roles(
        folders(("INBOX", ()), ("Sent", ("\\Sent",)), ("Ausgang", ())),
        overrides={"sent": "ausgang", "archive": "Nope"},
    )
    assert roles["Ausgang"] == "sent"
    assert "Sent" not in roles
    assert warnings == ["folder override archive='Nope': no such folder"]


def test_special_use_can_be_disabled():
    roles, _ = assign_roles(folders(("INBOX", ()), ("X", ("\\Sent",))), use_special_use=False)
    assert roles == {"INBOX": "inbox"}


def test_roles_ignore_other_users_and_shared_namespaces():
    folders = [
        RawFolder("INBOX", "INBOX", "/", ()),
        RawFolder("Shared/team/Sent", "Shared/team/Sent", "/", ("\\Sent",)),
        RawFolder("Other Users/bob/Trash", "Other Users/bob/Trash", "/", ("\\Trash",)),
        RawFolder("Shared", "Shared", "/", ("\\Noselect",)),
        RawFolder("Gesendet", "Gesendet", "/", ()),
    ]
    roles, _ = assign_roles(folders, foreign_prefixes=("Shared/", "Other Users/", ""))
    assert roles == {"INBOX": "inbox", "Gesendet": "sent"}
    # an explicit override may still point into a shared namespace
    roles, _ = assign_roles(
        folders, overrides={"trash": "Other Users/bob/Trash"}, foreign_prefixes=("Other Users/",)
    )
    assert roles["Other Users/bob/Trash"] == "trash"
