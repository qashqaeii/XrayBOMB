
def test_build_command_panel():
    from tools.server_provisioning import build_command

    cmd, timeout = build_command("panel_3xui_sanaei")
    assert "MHSanaei" in cmd
    assert timeout >= 300


def test_build_command_ssl_requires_domain():
    from tools.server_provisioning import build_command

    try:
        build_command("ssl_certbot")
    except ValueError as e:
        assert "Domain" in str(e)
    else:
        raise AssertionError("expected ValueError")

    cmd, _ = build_command("ssl_certbot", domain="vpn.example.com", email="a@b.com")
    assert "certbot" in cmd
    assert "vpn.example.com" in cmd


def test_action_groups():
    from tools.server_provisioning import ACTION_GROUPS, actions_for_group

    assert "Panels" in ACTION_GROUPS
    assert any(a.id == "panel_marzban" for a in actions_for_group("Panels"))
