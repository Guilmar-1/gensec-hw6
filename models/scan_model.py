from models.db import get_db

class ScanModel:
    @staticmethod
    def create_scan(target_url):
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO scans (target_url, status) VALUES (?, 'pending')",
            (target_url,)
        )
        db.commit()
        return cursor.lastrowid

    @staticmethod
    def update_scan_status(scan_id, status, total_vulnerabilities=0):
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            """
            UPDATE scans
            SET status = ?,
                end_time = CURRENT_TIMESTAMP,
                total_vulnerabilities = ?
            WHERE id = ?
            """,
            (status, total_vulnerabilities, scan_id)
        )
        db.commit()

    @staticmethod
    def get_scan(scan_id):
        db = get_db()
        return db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()

    @staticmethod
    def get_all_scans():
        db = get_db()
        return db.execute("SELECT * FROM scans ORDER BY start_time DESC").fetchall()

    @staticmethod
    def delete_scan(scan_id):
        db = get_db()
        db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        db.commit()
