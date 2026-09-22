from hypersearch.cli import parser


def test_serve_public_host_is_configurable():
    args = parser().parse_args(["serve", "--public-host", "git.example.test"])
    assert args.public_host == "git.example.test"
