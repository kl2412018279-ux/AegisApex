"""In-memory stand-in for the parts of the supabase-py client the agent uses."""
import uuid


class _Result:
    def __init__(self, data):
        self.data = data


class _Query:
    def __init__(self, db, table):
        self.db, self.table, self.filters, self.op, self.payload, self._limit = db, table, [], "select", None, None

    def select(self, *_):
        self.op = "select"
        return self

    def insert(self, payload):
        self.op, self.payload = "insert", payload
        return self

    def update(self, payload):
        self.op, self.payload = "update", payload
        return self

    def eq(self, col, val):
        self.filters.append((col, val, True))
        return self

    def neq(self, col, val):
        self.filters.append((col, val, False))
        return self

    def limit(self, n):
        self._limit = n
        return self

    def _match(self, row):
        return all((row.get(c) == v) == positive for c, v, positive in self.filters)

    def execute(self):
        rows = self.db.tables.setdefault(self.table, [])
        if self.op == "insert":
            row = {"id": str(uuid.uuid4()), **self.payload}
            rows.append(row)
            return _Result([row])
        matched = [r for r in rows if self._match(r)]
        if self.op == "update":
            for r in matched:
                r.update(self.payload)
        return _Result(matched[: self._limit] if self._limit else matched)


class FakeSupabase:
    def __init__(self, **tables):
        self.tables = {k: list(v) for k, v in tables.items()}
        self.rpc_calls = []
        self.rpc_results = {}

    def table(self, name):
        return _Query(self, name)

    def rpc(self, name, params):
        self.rpc_calls.append((name, params))
        return _Query._RpcStub(self.rpc_results.get(name))


class _RpcStub:
    def __init__(self, data):
        self.data = data

    def execute(self):
        return _Result(self.data)


_Query._RpcStub = _RpcStub
