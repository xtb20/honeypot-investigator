import csv
import io
import unittest
from importer import connect, import_csv


def sample(rows):
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=['_index','_id','Type (type)','@timestamp','sensor','session','eventid','input'])
    writer.writeheader()
    for row in rows:
        base = {'_index':'test','_id':'1','Type (type)':'Cowrie','@timestamp':'Oct 18, 2026 @ 12:00:00.000',
                'sensor':'a','session':'s','eventid':'cowrie.command.input','input':'echo example'}
        writer.writerow(base | row)
    stream.seek(0)
    return stream


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.db = connect(':memory:')

    def tearDown(self):
        self.db.close()

    def test_duplicates_and_other_sensors(self):
        rows = [{}, {'_id':'2','Type (type)':'NGINX'}]
        self.assertEqual(import_csv(sample(rows),self.db), dict(read=2,imported=1,duplicates=0,skipped=1,extra_column_rows=0))
        self.assertEqual(import_csv(sample(rows),self.db)['duplicates'],1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)

    def test_sensor_scoping_and_index_identity(self):
        import_csv(sample([{}, {'_index':'other','sensor':'b'}]),self.db)
        self.assertEqual(len(self.db.execute('SELECT sensor,session FROM events GROUP BY sensor,session').fetchall()),2)

    def test_invalid_timestamp_rolls_back(self):
        with self.assertRaises(ValueError):
            import_csv(sample([{}, {'_id':'2','@timestamp':'bad'}]),self.db)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)


if __name__ == '__main__':
    unittest.main()
