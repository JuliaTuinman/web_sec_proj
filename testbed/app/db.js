// Single place where the app obtains its MongoDB handle.
// The MQM teammate wraps the driver HERE (see protections/mqm.js hook), so
// every query in every route goes through the same wrapped collection objects.
const { MongoClient } = require('mongodb');

const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'testbed';

let db;

async function connect() {
  const client = new MongoClient(MONGO_URL);
  await client.connect();
  db = client.db(DB_NAME);

  // Optional driver-level protection (MQM). Must return the db (or a wrapper).
  const protection = require('./protections').load();
  if (protection.wrapDb) db = protection.wrapDb(db);
  return db;
}

function getDb() {
  if (!db) throw new Error('DB not connected yet');
  return db;
}

module.exports = { connect, getDb };
