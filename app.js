//验证中间件 token:token  nonce:'随机字符串' timestamp:'时间戳' sign:'签名'
exports.auth = function* (next) {
  try{
    const data = this.query;
    console.log('auth data-->>',data);
    if(!data.token || !data.nonce || !data.timestamp || !data.sign){
      this.body = lockMessage;
      return;
    };
    const token = data.token
      , nonce = data.nonce
      , sign = data.sign
      , timestamp = +data.timestamp;
    //检验timestamp
    if(timestamp > Date.now() || Date.now() - timestamp > global.URL_timeOut){
      this.body = time_auth;
      return;
    };
    //检验token
    const token_value = yield redisCli.get(token);
    if(!token_value){
      this.body = token_auth;
      return;
    };
    const appInfo = JSON.parse(token_value);
    //检验appId 的router权限
    const appId = appInfo.appId;
    console.log('appId-->>',appId);
    let flagInfo = findSecretByAppId(appId);
    if(!flagInfo){
      this.body = appId_secret_err;
      return;
    };
    const reqPath = this.path; // /xxx/x/x
    let flag_router = flagInfo.access_router.every((d) => d !== 'ALL' && d !== reqPath);
    if(flag_router){
      this.body = router_auth;
      return;
    };
    //检验signature
    /**
     * 生成签名 signature
     */
    // extra.createSign = function (token,timestamp,appId,appSecret,nonce) {
    // 	const hmac = crypto.createHmac('sha1',appSecret);
    // 	hmac.update(token);
    // 	hmac.update(timestamp);
    // 	hmac.update(appId);
    // 	hmac.update(appSecret);
    // 	hmac.update(nonce);
    // 	return hmac.digest('hex');
    // }
    const real_signature = utils.createSign(token,timestamp.toString(),appId,
      flagInfo.appSecret,nonce);
    if(real_signature !== sign){
      this.body = sign_auth;
      return;
    };
    yield next;
  }catch (err){
    console.log('err--->>',err);
    this.body = err;
  }
}