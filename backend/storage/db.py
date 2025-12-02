class Database:
    def __init__(self, db_path):
        self.db_path = db_path

    def connect(self):
        """
        Connect to DuckDB.
        """
        pass

    def query(self, sql, params=None):
        """
        Execute a query.
        """
        pass
