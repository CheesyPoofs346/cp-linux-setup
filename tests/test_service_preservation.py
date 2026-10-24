import importlib.util
from pathlib import Path
import unittest
import os
import tempfile

def module():
    path=Path(__file__).resolve().parents[1]/'lib/service_policy.py'
    spec=importlib.util.spec_from_file_location('service_policy',path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod

class ServicePreservationTests(unittest.TestCase):
    def test_hba_changes_only_authentication_field(self):
        source='local trust all trust # trust database\nhost all trust 127.0.0.1/32 trust\n'
        self.assertEqual(module().pg_hba(source),'local trust all peer # trust database\nhost all trust 127.0.0.1/32 scram-sha-256\n')

    def test_nginx_does_not_shadow_inherited_headers(self):
        source='http { add_header Strict-Transport-Security "max-age=31536000" always; server { listen 443; } }'
        out=module().nginx_text(source)
        self.assertNotIn('add_header',out.split('server {',1)[1])
        self.assertIn('add_header X-Content-Type-Options nosniff always;',out.split('server {',1)[0])

    @unittest.skipUnless(os.name=='posix','POSIX permissions')
    def test_web_permissions_preserve_group_write_and_skip_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);web=root/'site';web.mkdir();web.chmod(0o777)
            page=web/'page';page.write_text('business');page.chmod(0o666)
            outside=root/'outside';outside.write_text('keep');outside.chmod(0o666)
            (web/'link').symlink_to(outside)
            module().secure_webroots([web])
            self.assertEqual(web.stat().st_mode&0o777,0o775)
            self.assertEqual(page.stat().st_mode&0o777,0o664)
            self.assertEqual(outside.stat().st_mode&0o777,0o666)

    def test_pg_preserves_data_and_peer(self):
        m=module()
        text="data_directory = '/srv/db'\narchive_command = 'cp %p /backup/%f'\nlisten_addresses = '*'\n"
        out=m.pg_settings(text,{'listen_addresses':"'localhost'"})
        self.assertIn("data_directory = '/srv/db'",out)
        self.assertIn("archive_command = 'cp %p /backup/%f'",out)
        self.assertEqual(out,m.pg_settings(out,{'listen_addresses':"'localhost'"}))
        hba='local all all peer\nhost finance analyst 10.0.0.0/24 trust\nhost all all ::1/128 md5\n'
        hardened=m.pg_hba(hba)
        self.assertIn('local all all peer',hardened)
        self.assertIn('host finance analyst 10.0.0.0/24 scram-sha-256',hardened)
        self.assertIn('::1/128 md5',hardened)

    def test_nginx_preserves_api_and_tls_without_duplicates(self):
        m=module()
        text='http {\n ssl_prefer_server_ciphers on;\n server { listen 80; location /api/ { proxy_pass http://127.0.0.1:8081/; } autoindex on; }\n}\n'
        out=m.nginx_text(text)
        self.assertEqual(out.count('ssl_prefer_server_ciphers'),1)
        self.assertIn('proxy_pass http://127.0.0.1:8081/',out)
        self.assertNotIn('autoindex on;',out)
        self.assertEqual(out,m.nginx_text(out))

    def test_nginx_exact_hidden_location_cannot_override_denial(self):
        out=module().nginx_text('server { location = /.env { root /srv/site; } }')
        self.assertIn('return 403;',out)

    def test_nginx_braces_in_strings_and_comments(self):
        source='http { # } fake server {\n log_format custom "{hello}"; server { location / { return 200 "}"; } } }'
        out=module().nginx_text(source)
        self.assertIn('log_format custom "{hello}";',out)
        self.assertEqual(out.count('location ~ /\\.'),1)

    def test_samba_keeps_business_paths_and_groups(self):
        m=module()
        text='[global]\n workgroup = BUSINESS\n[projects]\n path = /srv/research\n force user = analyst\n guest ok = yes\n'
        out=m.samba_text(text,{'projects':'research'})
        self.assertIn('workgroup = BUSINESS',out)
        self.assertIn('path = /srv/research',out)
        self.assertIn('valid users = @research',out)
        self.assertEqual(out,m.samba_text(out,{'projects':'research'}))

if __name__=='__main__': unittest.main()
