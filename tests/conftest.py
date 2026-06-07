import pytest


@pytest.fixture
def sample_urls() -> list[str]:
    return [
        "https://admin.target.com/login.php?id=1",
        "https://api.target.com/v1/users?user_id=100",
        "https://www.target.com/search?q=test",
        "https://target.com/graphql",
    ]


@pytest.fixture
def sample_subdomains() -> list[str]:
    return [
        "admin.target.com",
        "api.target.com",
        "www.target.com",
        "mail.target.com",
    ]
