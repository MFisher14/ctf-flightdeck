# KNX Secure known-answer fixture

`xknx_SecureTest.knxkeys` is the ETS 5.7.7 keyring that the xknx project ships as test data
(`test/secure_tests/resources/SecureTest.knxkeys`, keyring password `test`), copied unchanged
(sha256 `cd82c69e7a3fe13259a37fdd96219337fe44f52ab08eb79e1daef4c439f5c34d`). It holds only demo
keys for a test project. It is the independent oracle for `tests/test_sec_bas_knx_secure.py`:
an ETS-made signature, ETS-encrypted keys, and the Data Secure telegrams xknx's own tests
decode with them.

Source: the xknx project (github.com/XKNX/xknx), copyright the xknx authors, MIT licensed. No
xknx code is copied into this repo: the helper was written from the KNX algorithms and checked
against these vectors. The upstream LICENSE file has no separate copyright line (checked
2026-11-12); its permission notice, which the MIT licence requires with any copy, follows
unchanged.

## xknx licence (MIT)

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
