import os


def get_makefile_template(template_path=None):
    if not template_path:
        template_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "Makefile.template"
        )
    with open(template_path, "r") as fp:
        mk_tmpl = fp.read()
    return mk_tmpl


def generate_makefile(template_path=None, **kwargs):
    return get_makefile_template(template_path).format(**kwargs)
