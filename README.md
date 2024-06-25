## 주요정보통신기반시설 기술적 취약점 분석 평가 상세 가이드에 따른 조치 Shell Script

Step 1. git clone
<pre>
<code>
git clone https://github.com/paradox0909/cce.git
</code>
</pre>
Step 2. change directory
<pre>
<code>
cd cce
</code>
</pre>
Step 3. change mode (Permission Assignment)
<pre>
<code>
chmod +x main.sh
</code>
</pre>
Step 4. execute
<pre>
<code>
./main.sh
</code>
</pre>
* * *
# How to Fix the server
사용법 : 
--fix 인자를 사용해주세요.

<pre>
<code>
./main.sh --fix
</code>
</pre>

## 주의 : --fix 인자 사용 시, 서버 내 파일의 내용이 임의로 삭제되거나 바뀔 수 있으므로, 백업을 하고 사용할 것.