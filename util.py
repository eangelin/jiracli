import contextlib
import tempfile
import shutil
import codecs

@contextlib.contextmanager
def TemporaryDirectory(basedir):
    name = tempfile.mkdtemp(dir=basedir)
    try:
        yield name
    finally:
        try:
            shutil.rmtree(name)
        except OSError as e:
            if e.errono != errno.ENOENT:
                raise

def create_file(path):
    with open(path, 'a') as f:
        pass

def slurp_enc(path, encoding, errors='strict'):
    try:
        with codecs.open(path, 'r', encoding, errors) as f:
            return f.read()
    except UnicodeDecodeError as e:
        return None

def slurp(path):
    encs = [('utf-8', 'strict'),
            ('latin-1', 'strict'),
            ('ascii', 'replace')]
    for enc, errors in encs:
        result = slurp_enc(path, enc, errors)
        if result is not None:
            return result
    return None

    
        


