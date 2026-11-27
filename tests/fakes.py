from typing import Any, Callable, Optional, Union

Outcome = Union[Any, Callable[[Any], Any]]


class FakeCursor:
    """Cursor that answers each SQL statement from a list of routes.

    The first route whose text appears in the statement decides the result.
    A route result may be a value or a callable that receives the parameters
    and returns the value. An exception instance or class is raised instead.

    Parameters
    ----------
    database : FakeDatabase
        Database that owns the routes and records the statements.

    Example
    -------
    >>> cursor = FakeCursor(FakeDatabase([("SELECT 1", (1,))]))
    """

    def __init__(self, database: "FakeDatabase") -> None:
        """Start an empty cursor that shares the database routes.

        Parameters
        ----------
        database : FakeDatabase
            Database that owns the routes and records the statements.

        Returns
        -------
        None
        """
        self._database = database
        self._result = None
        self.rowcount = 0

    def execute(
        self,
        sql: str,
        params: Optional[tuple] = None,
    ) -> None:
        """Record a statement and prepare the matching result.

        Parameters
        ----------
        sql : str
            SQL text of the statement.
        params : tuple | None
            Parameters sent with the statement.

        Returns
        -------
        None
        """
        self._database.statements.append((" ".join(sql.split()), params))
        self._result = None
        self.rowcount = 0
        for needle, outcome in self._database.routes:
            if needle in sql:
                value = outcome(params) if callable(outcome) else outcome
                if isinstance(value, BaseException) or (
                    isinstance(value, type) and issubclass(value, BaseException)
                ):
                    raise value
                self._result = value
                self.rowcount = 1
                return

    def fetchone(self) -> Any:
        """Return the prepared row of the last statement.

        Returns
        -------
        Any
            Prepared row, or None.
        """
        return self._result

    def fetchall(self) -> list:
        """Return the prepared rows of the last statement.

        Returns
        -------
        list
            Prepared rows, or an empty list.
        """
        return list(self._result or [])

    def __enter__(self) -> "FakeCursor":
        """Enter the cursor context.

        Returns
        -------
        FakeCursor
            This cursor.
        """
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        """Leave the cursor context without suppressing errors.

        Returns
        -------
        bool
            Always False.
        """
        return False


class FakeConnection:
    """Connection that exposes one cursor and tracks commit or rollback.

    Parameters
    ----------
    cursor : FakeCursor
        Cursor returned by ``cursor()``.
    database : FakeDatabase
        Database that records the outcome of each connection.

    Example
    -------
    >>> connection = FakeConnection(FakeCursor(FakeDatabase()), FakeDatabase())
    """

    def __init__(self, cursor: FakeCursor, database: "FakeDatabase") -> None:
        """Store the cursor and the database that records the outcome.

        Parameters
        ----------
        cursor : FakeCursor
            Cursor returned by ``cursor()``.
        database : FakeDatabase
            Database that records the outcome of each connection.

        Returns
        -------
        None
        """
        self._cursor = cursor
        self._database = database

    def cursor(self) -> FakeCursor:
        """Return the cursor of this connection.

        Returns
        -------
        FakeCursor
            Cursor that answers the statements of this connection.
        """
        return self._cursor

    def __enter__(self) -> "FakeConnection":
        """Enter the connection context.

        Returns
        -------
        FakeConnection
            This connection.
        """
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        """Record a commit, or a rollback when an exception leaves the block.

        Parameters
        ----------
        exc_type : type | None
            Exception class, when one is leaving the block.
        exc : BaseException | None
            Exception instance, when one is leaving the block.
        traceback : Any
            Traceback of the exception.

        Returns
        -------
        bool
            Always False, so exceptions propagate.
        """
        self._database.outcomes.append("rollback" if exc_type else "commit")
        return False


class FakeDatabase:
    """Fake of the psycopg2 connection factory used by the routers.

    Parameters
    ----------
    routes : list[tuple[str, Outcome]] | None
        Pairs of SQL fragment and outcome, checked in order.

    Example
    -------
    >>> database = FakeDatabase([("FROM pgl_proxy.students", None)])
    """

    def __init__(self, routes: Optional[list] = None) -> None:
        """Store the routes and start with no recorded statements.

        Parameters
        ----------
        routes : list[tuple[str, Outcome]] | None
            Pairs of SQL fragment and outcome, checked in order.

        Returns
        -------
        None
        """
        self.routes = list(routes or [])
        self.statements: list = []
        self.outcomes: list = []

    def connect(self) -> FakeConnection:
        """Open a new fake connection.

        Returns
        -------
        FakeConnection
            Connection that answers from this database's routes.
        """
        return FakeConnection(FakeCursor(self), self)

    def statements_containing(self, fragment: str) -> list:
        """List the recorded statements that include a fragment.

        Parameters
        ----------
        fragment : str
            Text searched in each statement.

        Returns
        -------
        list
            Pairs of ``(sql, params)`` that include the fragment.
        """
        return [item for item in self.statements if fragment in item[0]]
