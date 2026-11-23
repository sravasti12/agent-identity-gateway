import argparse
import sqlite3
from contextlib import closing
from pathlib import Path

from app.audit.store import ChainResult, Database


def verify_file(path: Path) -> ChainResult:
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        return Database.verify_connection(db)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an existing audit chain without modifying storage")
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    try:
        result = verify_file(args.database)
    except sqlite3.Error:
        print('{"error":"audit_database_unavailable"}')
        return 2
    print(result.model_dump_json())
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
