import itertools
import sys
import time
import os
import psutil
from datetime import timedelta
from multiprocessing import Pool, cpu_count, Manager


def generate_keys_segment(keys_segment, output_file_path, keys_generated, start_time):
    for _ in range(1000):  # 각 프로세스에서 1000개의 키를 생성
        for key in keys_segment:
            with open(output_file_path, 'ab') as file:
                # 키를 바이너리 파일에 추가
                file.write(bytes(key))
            keys_generated.value += 1
            display_progress(keys_generated.value, start_time)


def display_progress(keys_generated, start_time):
    total_keys = 2**56
    progress = (keys_generated / total_keys) * 100
    elapsed_time = time.time() - start_time
    cpu_percent = psutil.cpu_percent(interval=1)  # 1초 동안의 CPU 사용량
    sys.stdout.write(f"\r진행 상황: {keys_generated}/{total_keys} ({progress:.2f}%), 소요 시간: {timedelta(seconds=elapsed_time)}, CPU 사용률: {cpu_percent}%")
    sys.stdout.flush()


def generate_keys():
    # DES 암호화에서 사용되는 키 후보군 생성
    keys = itertools.product(range(256), repeat=8)

    output_file_path = 'all_des_keys.bin'
    with open(output_file_path, 'wb') as _:
        pass  # 파일 초기화

    manager = Manager()
    keys_generated = manager.Value('i', 0)

    # CPU 코어 수의 10배 만큼 프로세스 풀 생성
    pool = Pool(processes=cpu_count() * 50)

    start_time = time.time()
    results = []

    # 1000개의 키씩 나누어서 프로세스에 할당
    for chunk in chunks(keys, 1000):
        result = pool.apply_async(generate_keys_segment, (list(chunk), output_file_path, keys_generated, start_time))
        results.append(result)

    # 모든 작업이 완료될 때까지 기다림
    for result in results:
        result.get()

    pool.close()
    pool.join()

    # 작업 완료
    print("\n작업 완료")

    # 바이너리 파일의 크기 출력
    file_size = os.path.getsize(output_file_path)
    print(f"생성된 바이너리 파일 크기: {file_size} bytes")


def chunks(iterable, chunk_size):
    """리스트를 chunk_size 크기의 청크로 나누는 제너레이터 함수"""
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) == chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def main():
    generate_keys()


if __name__ == "__main__":
    main()