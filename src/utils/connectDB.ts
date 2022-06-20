import mongoose from 'mongoose';
import config from 'config';

const localUri = config.get<string>('dbUri');

async function connectDB() {
  try {
    await mongoose.connect(localUri);
    console.log('🚀 Database connected successfully');
  } catch (error: any) {
    console.log(error.message);
    setTimeout(connectDB, 5000);
  }
}

export default connectDB;
