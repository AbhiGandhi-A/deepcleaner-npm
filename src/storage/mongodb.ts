import { MongoClient } from 'mongodb';
import type { ScanResult } from '../models/scan-result.js';
import { loadEnv } from '../utils/env.js';

export interface MongoSaveResult {
  success: boolean;
  insertedId?: string;
  database?: string;
  collection?: string;
  error?: string;
}

export function getMongoUri(uri?: string): string | undefined {
  if (uri !== undefined) return uri.trim() || undefined;
  loadEnv();
  const found =
    process.env.MONGODB_URI ||
    process.env.MONGO_URI ||
    process.env.MONGODB_URL ||
    process.env.MONGO_URL ||
    process.env.DATABASE_URL;

  return found ? found.trim() : undefined;
}

export async function saveScanResultToMongo(
  result: ScanResult,
  uri?: string
): Promise<MongoSaveResult> {
  const mongoUri = getMongoUri(uri);

  if (!mongoUri) {
    return {
      success: false,
      error: 'MongoDB URI is not provided or set in MONGODB_URI environment variable.'
    };
  }

  if (!mongoUri.startsWith('mongodb://') && !mongoUri.startsWith('mongodb+srv://')) {
    return {
      success: false,
      error: 'Invalid MongoDB connection scheme: must start with mongodb:// or mongodb+srv://'
    };
  }

  let client: MongoClient | undefined;
  try {
    client = new MongoClient(mongoUri, {
      serverSelectionTimeoutMS: 8000,
      connectTimeoutMS: 8000
    });

    await client.connect();
    const db = client.db('deepcleaner');
    const collection = db.collection('scans');

    const doc = {
      ...result,
      createdAt: new Date()
    };

    const res = await collection.insertOne(doc);
    return {
      success: true,
      insertedId: res.insertedId.toString(),
      database: 'deepcleaner',
      collection: 'scans'
    };
  } catch (err: any) {
    return {
      success: false,
      error: err?.message || String(err)
    };
  } finally {
    if (client) {
      try {
        await client.close();
      } catch {
        // ignore
      }
    }
  }
}

export async function testMongoConnection(uri?: string): Promise<{ connected: boolean; message: string; version?: string }> {
  const mongoUri = getMongoUri(uri);
  if (!mongoUri) {
    return { connected: false, message: 'MONGODB_URI is not configured' };
  }

  if (!mongoUri.startsWith('mongodb://') && !mongoUri.startsWith('mongodb+srv://')) {
    return {
      connected: false,
      message: 'Invalid MongoDB connection scheme: must start with mongodb:// or mongodb+srv://'
    };
  }

  let client: MongoClient | undefined;
  try {
    client = new MongoClient(mongoUri, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 5000
    });

    await client.connect();
    const admin = client.db('admin');
    await admin.command({ ping: 1 });
    return {
      connected: true,
      message: 'MongoDB database connected successfully'
    };
  } catch (err: any) {
    return {
      connected: false,
      message: err?.message || String(err)
    };
  } finally {
    if (client) {
      try {
        await client.close();
      } catch {
        // ignore
      }
    }
  }
}
