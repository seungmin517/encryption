import sys
import time

# 출력을 갱신하여 진행 상황 표시
for i in range(11):
    # 이전 출력 삭제
    sys.stdout.write('\r')
    sys.stdout.flush()

    # 새로운 출력으로 덮어쓰기
    sys.stdout.write(f'진행 상황: {i}/10')
    sys.stdout.flush()

    # 잠시 대기
    time.sleep(1)

print("\n작업 완료")
