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
  if (uri !== undefined) return uri;
  loadEnv();
  return (
    process.env.MONGODB_URI ||
    process.env.MONGO_URI ||
    process.env.MONGODB_URL ||
    process.env.MONGO_URL ||
    process.env.DATABASE_URL
  );
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

  const client = new MongoClient(mongoUri, {
    serverSelectionTimeoutMS: 8000,
    connectTimeoutMS: 8000
  });

  try {
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
    try {
      await client.close();
    } catch {
      // ignore
    }
  }
}

export async function testMongoConnection(uri?: string): Promise<{ connected: boolean; message: string; version?: string }> {
  const mongoUri = getMongoUri(uri);
  if (!mongoUri) {
    return { connected: false, message: 'MONGODB_URI is not configured' };
  }

  const client = new MongoClient(mongoUri, {
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 5000
  });

  try {
    await client.connect();
    const admin = client.db('admin');
    const info = await admin.command({ ping: 1 });
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
    try {
      await client.close();
    } catch {
      // ignore
    }
  }
}

