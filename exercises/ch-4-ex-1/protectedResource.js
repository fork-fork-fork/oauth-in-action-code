var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var qs = require("qs");
var querystring = require('querystring');
var request = require("sync-request");
var __ = require('underscore');
var base64url = require('base64url');
var jose = require('jsrsasign');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
    "name": "Protected Resource",
    "description": "This data has been protected by OAuth 2.0"
};

// 핼퍼 함수에서 토큰 스캔
var getAccessToken = function(req, res, next) { // next: 요청을 계속해서 처리

    // http 요청에 인가 헤더가 포함되어 있다면, OAuth Bearer 토큰이 포함돼 있는지 확인
    var inToken = null;
    var auth = req.headers['authorization'];
    if (auth && auth.toLowerCase().indexOf('bearer') == 0) { // [첫번째 방법] authorization과 bearer 문자열이 존재한다면, 헤더에서 토큰 값 추출
        inToken = auth.slice('bearer '.length);
    } else if (req.body && req.body.access_token) { // [두번째 방법] 인코딩된 폼으로 토큰이 전달됨: 토큰 값이 존재하는지 확인
        // not in the header, check in the form body
        inToken = req.body.access_token;
    } else if (req.query && req.query.access_token) { // [세번째 방법] 질의 파라미터로 전달되는 토큰 처리
        inToken = req.query.access_token
    }

    console.log('Incoming token: %s', inToken);

    // 토큰이 저장되어 있는지  확인하기 위한 데이터베이스의 검색 기능 이용
    nosql.one().make(function(builder) {
        builder.where('access_token', inToken); // 입력된 토큰이 저장된 액세스 토큰과 동일한지 비교
        builder.callback(function(err, token) { // 일치하는 것이 발견되거나, 모든 데이터베이스 검색이 수행되었을 때 호출됨
            if (token) {
                console.log("We found a matching token: %s", inToken);
            } else {
                console.log('No matching token was found.');
            };
            req.access_token = token; // 동일한 토큰의 발견 여부와 상관없이, 토큰 값은 req 객체에 할당됨
            next(); // req 객체는 자동으로 프로세스 핸들러의 다음 부분으로 전달됨
            // 전달되는 토큰 객체는 인가 서버가 토큰을 만들 때 저장한 토큰과 동일한 것
            return;
        });
    });
};

app.options('/resource', cors());

// 핸들러 정의, 그리고 가장 먼저 호출되길 원하는 함수 차례로 추가
app.post("/resource", cors(), getAccessToken, function(req, res){

    // 핸들러가 호출될 때, 요청 객체에는 access_token이 포함되어 있음
    // access_token 값이 있거나, null 이거나 조건에 따라 처리됨
    if (req.access_token) {
        res.json(resource);
    } else {
        res.status(401).end();
    }

});

var server = app.listen(9002, 'localhost', function () {
    var host = server.address().address;
    var port = server.address().port;

    console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});

