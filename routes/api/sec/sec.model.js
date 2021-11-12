var conn = require('../../../utils/dao');
var ObjectID = require('mongodb').ObjectId;
const bcrypt = require("bcryptjs");
var _db;
class Sec {
  secColl = null;
  constructor() {
    this.initModel();
  }
  async initModel() {
    try {
      _db = await conn.getDB();
      this.secColl = await _db.collection("users");
    } catch (ex) {
      console.log(ex);
      process.exit(1);
    }
  }
  async createNewUser( email, password) {
    try {
      let user = {
        email: email,
        password: await bcrypt.hash(password, 10),
        lastlogin: null,
        lastpasswordchange: null,
        passwordexpires: new Date().getTime() + (90 * 24 * 60 * 60 * 1000), 
        oldpasswords: [],
        roles:["public"]
      }
      let result = await this.secColl.insertOne(user);
      //console.log(result);
      return result;
    } catch(ex) {
      console.log(ex);
      throw(ex);
    }
  }

  async getByEmail(email){
    const filter = {"email": email};
    return await this.secColl.findOne(filter);
  }

  async comparePassword (rawPassword, dbPassword){
    return await bcrypt.compare(rawPassword, dbPassword);
  }

/*Reset Password*/

async updateResetToken(token,id,callback=(err,result)=>{}){
  try{
    const filter = {"_id": new ObjectID(id)};
    const update = {"$set":{resetUrl:token}};
    let result = await this.secColl.updateOne(filter,update);
    callback(null,{...result,token})
  }catch(ex){
    callback(ex,"")
    //throw(ex);
  }
}

async resetPassword(id,password,callback=(err,result)=>{}){
  try {
    const filter = {"_id": new ObjectID(id)};
    const update = {"$set":{password:await bcrypt.hash(password, 10),lastpasswordchange:new Date()}};
    let result = await this.secColl.updateOne(filter,update);
    callback(null,result)
  } catch (error) {
    callback(error,"")
    //throw(error);
  }
}

async findByToken(token){
  const filter = {"resetUrl":token}
  return await this.secColl.findOne(filter);
}


}



module.exports = Sec;
