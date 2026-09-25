const db = require('../backend/db');

async function runTest() {
  const seqRes = await db.query("SELECT pg_get_serial_sequence('students', 'id') as seq");
  console.log('Actual Sequence Name:', seqRes.rows[0].seq);

  async function resetIfEmpty() {
    await db.query(`
      SELECT CASE 
        WHEN (SELECT COUNT(*) FROM students) = 0 
        THEN setval(pg_get_serial_sequence('students', 'id'), 1, false) 
      END
    `);
  }

  async function insertStudent(name) {
    await resetIfEmpty();
    const res = await db.query(
      'INSERT INTO students (name, roll_no, course, attendance) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, '101', 'CS', 90]
    );
    return res.rows[0];
  }

  await db.query('DELETE FROM students');
  console.log('Cleared all students.');

  const s1 = await insertStudent('First Student');
  console.log('Test 1 (empty table insert):', s1.id === 1 ? 'PASS (ID=1)' : 'FAIL (ID=' + s1.id + ')');

  const s2 = await insertStudent('Second Student');
  console.log('Test 2 (second insert):', s2.id === 2 ? 'PASS (ID=2)' : 'FAIL (ID=' + s2.id + ')');

  await db.query('DELETE FROM students WHERE id = $1', [s1.id]);
  const s3 = await insertStudent('Third Student');
  console.log('Test 3 (deleted 1, 2 remains, insert 3):', s3.id === 3 ? 'PASS (ID=3)' : 'FAIL (ID=' + s3.id + ')');

  await db.query('DELETE FROM students');
  const s4 = await insertStudent('Fresh Student');
  console.log('Test 4 & 5 (clear all, insert):', s4.id === 1 ? 'PASS (ID=1)' : 'FAIL (ID=' + s4.id + ')');

  // Clean test data
  await db.query('DELETE FROM students');
  process.exit(0);
}

runTest().catch(err => {
  console.error(err);
  process.exit(1);
});
