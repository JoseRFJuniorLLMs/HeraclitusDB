import importlib.util, pathlib, unittest, sys
P=pathlib.Path(__file__).parents[1]/'runner.py'; spec=importlib.util.spec_from_file_location('runner',P); m=importlib.util.module_from_spec(spec); sys.modules[spec.name]=m; spec.loader.exec_module(m)
class Guard(unittest.TestCase):
    def base(self): return {'core_rest':'http://127.0.0.1:1','agent_api':'http://localhost:2','otlp':'http://[::1]:3','mcp_gateway':'http://127.0.0.1:4','upstream_hits':'http://127.0.0.1:5/hits'}
    def test_loopback_ok(self): m.Lab(self.base())
    def test_remote_rejected(self):
        c=self.base(); c['mcp_gateway']='https://example.com'
        with self.assertRaises(SystemExit): m.Lab(c)
    def test_no_remote_escape_hatch(self):
        text=P.read_text(); self.assertNotIn('--allow-remote',text)
if __name__=='__main__': unittest.main()
