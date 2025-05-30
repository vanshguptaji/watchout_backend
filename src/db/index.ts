import mongoose from 'mongoose';

const connectDB = async (): Promise<void> => {
    try {
        const connectionInstance = await mongoose.connect(`${process.env.MONGODB_URL}`);
        console.log(`\nMongoDB connected !! DB HOST: ${connectionInstance.connection.host}`);
    } catch (error) {
        console.log(process.env.MONGODB_URL)
        console.log("MONGODB connection error :", error);
        process.exit(1);
    }
};

export default connectDB;