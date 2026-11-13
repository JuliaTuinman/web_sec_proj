// Wipes and re-seeds the testbed DB. Deterministic, so every run starts identical.
// Passwords are plaintext ON PURPOSE (the login endpoint compares them in the query).
const { MongoClient } = require('mongodb');

const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'testbed';

const users = [
  { username: 'admin',   password: 'Adm1n!SuperSecret', role: 'admin', email: 'admin@example.com',   secret: 'FLAG{admin_secret_token}' },
  { username: 'alice',   password: 'alice123',          role: 'user',  email: 'alice@example.com',   secret: 'alice-api-key-1111' },
  { username: 'bob',     password: 'bobpass',           role: 'user',  email: 'bob@example.com',     secret: 'bob-api-key-2222' },
  { username: 'carol',   password: 'carol!pw',          role: 'user',  email: 'carol@example.com',   secret: 'carol-api-key-3333' },
  { username: 'dave',    password: 'dave2024',          role: 'user',  email: 'dave@example.com',    secret: 'dave-api-key-4444' },
  { username: 'erin',    password: 'erin-pass',         role: 'user',  email: 'erin@example.com',    secret: 'erin-api-key-5555' },
  { username: 'frank',   password: 'frank_pw9',         role: 'user',  email: 'frank@example.com',   secret: 'frank-api-key-6666' },
  { username: 'grace',   password: 'gracepw!',          role: 'user',  email: 'grace@example.com',   secret: 'grace-api-key-7777' },
  { username: 'heidi',   password: 'heidi#77',          role: 'user',  email: 'heidi@example.com',   secret: 'heidi-api-key-8888' },
  { username: 'ivan',    password: 'ivan4ever',         role: 'user',  email: 'ivan@example.com',    secret: 'ivan-api-key-9999' },
];

const catalog = {
  electronics: ['Laptop', 'Smartphone', 'Headphones', 'Tablet', 'Smartwatch', 'Monitor', 'Keyboard', 'Mouse'],
  books:       ['Novel', 'Cookbook', 'Textbook', 'Comic', 'Biography', 'Dictionary'],
  clothing:    ['T-Shirt', 'Jeans', 'Jacket', 'Sneakers', 'Hat', 'Scarf'],
  home:        ['Lamp', 'Chair', 'Desk', 'Blender', 'Kettle', 'Rug'],
};

// Deterministic pseudo-price so reruns are identical.
const products = [];
let n = 0;
for (const [category, names] of Object.entries(catalog)) {
  for (const name of names) {
    n++;
    products.push({
      name,
      category,
      price: 5 + ((n * 37) % 995),
      inStock: n % 4 !== 0,
    });
  }
}

async function main() {
  const client = new MongoClient(MONGO_URL);
  await client.connect();
  const db = client.db(DB_NAME);

  await db.collection('users').deleteMany({});
  await db.collection('products').deleteMany({});
  await db.collection('users').insertMany(users);
  await db.collection('products').insertMany(products);
  await db.collection('users').createIndex({ username: 1 }, { unique: true });
  await db.collection('products').createIndex({ category: 1 });

  console.log(`seeded ${users.length} users, ${products.length} products into "${DB_NAME}"`);
  await client.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
