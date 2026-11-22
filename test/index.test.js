import test from "node:test"; import assert from "node:assert/strict"; import { signToken, verifyToken, bearerToken, createOpaqueToken } from "../src/index.js";
const secret="0123456789abcdef0123456789abcdef";
test("signs and verifies claims",()=>{const token=signToken({sub:"u1"},secret,{now:1000,expiresIn:60});assert.equal(verifyToken(token,secret,{now:2000}).sub,"u1");});
test("rejects expired and tampered tokens",()=>{const token=signToken({sub:"u1"},secret,{now:1000,expiresIn:1});assert.throws(()=>verifyToken(token,secret,{now:3000}));assert.throws(()=>verifyToken(token+"x",secret));});
test("extracts bearer and generates opaque tokens",()=>{assert.equal(bearerToken("Bearer abc"),"abc");assert.equal(bearerToken("Basic abc"),null);assert.ok(createOpaqueToken().length>20);});