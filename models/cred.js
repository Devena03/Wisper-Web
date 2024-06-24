import mongoose from 'mongoose';

main().catch(err => console.log(err));

async function main() {
  await mongoose.connect('mongodb://localhost:27017/credential');
  console.log("Database connected");
}

const credSchema=new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  secret:{
    type:String,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  
});

const Cred=mongoose.model('Cred',credSchema);
export  default Cred;