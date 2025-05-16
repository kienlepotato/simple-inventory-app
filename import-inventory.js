const fs = require('fs');
const db = require('./db');

const inventoryData = JSON.parse(fs.readFileSync('inventory-data.json', 'utf8'));

db.serialize(() => {
  const stmt = db.prepare(`
    INSERT INTO inventory (name, quantity, location, supplier)
    VALUES (?, ?, ?, ?)
  `);

  inventoryData.forEach(item => {
    const { name, quantity, location, supplier } = item;
    stmt.run(name, quantity, location, supplier);
  });

  stmt.finalize(() => {
    console.log('Inventory data inserted successfully.');
    db.close();
  });
});
