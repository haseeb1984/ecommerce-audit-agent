from pathlib import Path


def test_admin_customer_directory_ignores_stale_search_and_pagination_responses():
    source = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert "let customerDirectoryRequestVersion = 0;" in source
    assert "const requestVersion=++customerDirectoryRequestVersion;" in source
    assert 'if(requestVersion!==customerDirectoryRequestVersion||search!==$("customerAccountSearch").value.trim())return;' in source
    assert 'const search=$("customerAccountSearch").value.trim();' in source


def test_admin_customer_detail_ignores_stale_account_responses_and_signout_invalidates_requests():
    source = (Path(__file__).resolve().parents[1] / "admin_portal.html").read_text()
    assert "let customerDetailRequestVersion = 0;" in source
    assert "const requestVersion=++customerDetailRequestVersion;" in source
    assert "if(requestVersion!==customerDetailRequestVersion" in source
    assert "customerDirectoryRequestVersion++;customerDetailRequestVersion++;" in source
    assert 'selectedCustomerEmail="";' in source
