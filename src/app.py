import sys
import logging
import smtplib
import hashlib
import time
import socket
import os
import datetime
import shutil
import tempfile
import psutil

# 윈도우 서버 정보 가져오기
def get_windows_server_info():

    # 윈도우 서버의 CPU 정보 가져오기
    cpu_info = psutil.cpu_percent(interval = 1, percpu = True)

    # 물리적인 CPU 코어의 수
    physical_cores = psutil.cpu_count(logical = False)
    
    # 논리적인 CPU의 수
    logical_cores = psutil.cpu_count(logical = True)

    # CPU의 주파수 정보
    cpu_freq = psutil.cpu_freq()

    return {'CPU 정보': cpu_info, 'CPU 코어 수' : physical_cores, 'CPU 쓰레드 수' : logical_cores, 'CPU ghz': cpu_freq}

# 카나리에 윈도우 서버 IP 주소 추가
def windows_server_ip_canary(canary_data):

    server_ip = socket.gethostbyname(socket.gethostbyname)

    return canary_data + server_ip

# 파일에 데이터 쓰기
def write_to_file(file_path, data):

    with open(file_path, 'w') as file:

        file.write(data)

# 파일에서 데이터 읽기
def read_from_file(file_path):

    with open(file_path, 'r') as file:

        return file.read()

# 파일 생성 시간을 반환하는 함수
def get_file_creation_time(file_path):

    return os.path.getctime(file_path)

# 카나리 무결성 검사
def check_integrity(canary, file_path):

    # 현재 카나리의 무결성을 확인하는 함수
    current_canary = hashlib.md5(read_from_file(file_path).encode()).hexdigest()

    return canary == current_canary

# 무결성 확인 및 훼손된 경우 로그 작성
def check_integrity(canary, file_path, log_file_path):

    current_canary = hashlib.md5(read_from_file(file_path).encode()).hexdigest()

    if canary != current_canary:

        log_message = f"무결성 훼손 발생 시각: {datetime.datetime.now()}, 파일 경로: {file_path}"

        write_to_file(log_file_path, log_message)

        return False

    return True


# 시그니처 훼손 검사
def check_signature_integrity(signature, file_path, log_file_path):

    try:

        with open(file_path, 'rb') as file:

            file_data = file.read()

        current_signature = hashlib.md5(file_data).hexdigest()  # 파일의 시그니처 계산

        if signature != current_signature:

            log_message = f"시그니처 훼손 발생 시각: {datetime.datetime.now()}, 파일 경로: {file_path}"

            write_to_file(log_file_path, log_message)  # 로그 파일에 훼손 로그 작성

            return False

        return True

    except Exception as e: # 예외 처리

        print(f"시그니처 훼손 검사 중 오류 발생: {e}")

        return False


# 악의적인 접근 시도 시에 프로세스 종료
def restrict_access():
    
    print("악의적인 접근이 감지되어 파일 접근이 제한됩니다.")
    
    logging.error("악의적인 접근이 감지되었습니다.")
    
    sys.exit(1)

# 파일에 접근한 시간을 로그로 저장하는 함수
def log_access_time(file_path, access_log_file_path):

    try:

        access_time = datetime.datetime.fromtimestamp(os.path.getatime(file_path))

        log_message = f"파일 접근 시간 - 파일 경로: {file_path}, 접근 시간: {access_time}"

        write_to_file(access_log_file_path, log_message)

    except Exception as e: # 예외 처리

        print(f"파일 접근 시간 로깅 중 오류 발생: {e}")

# 초기 시그니처 계산 함수
def calculate_file_signature(file_path):

    try:

        with open(file_path, 'rb') as file:

            file_data = file.read()

        return hashlib.md5(file_data).hexdigest()

    except Exception as e:

        print(f"시그니처 계산 중 오류 발생: {e}")

        return None

def main():

    # 사용자로부터 윈도우 서버의 IP 주소 입력 받기
    windows_server_ip = input("윈도우 서버의 IP 주소를 입력하세요 : ")

    # 입력 받은 IP 주소에 대한 윈도우 서버 정보 가져오기
    windows_server_info = get_windows_server_info()

    print(f"Windows Server Info for {windows_server_ip} : ", windows_server_info)

    # 윈도우 서버 정보를 기반으로 카나리 생성
    canary_data = str(windows_server_info)
    
    initial_canary = hashlib.md5(canary_data.encode()).hexdigest()

    # 카나리 파일 경로 지정
    canary_file_path = 'C:\\Users\\dsph9\\Desktop\\Canary.txt'

    # 초기 카나리 파일에 데이터 쓰기
    write_to_file(canary_file_path, canary_data)

     # 초기 카나리 파일의 생성 시간 기록
    initial_canary_creation_time = get_file_creation_time(canary_file_path)

    # log 파일 경로
    log_file_path = 'C:\\Users\\dsph9\\Desktop\\Anti_Log.log'

    # access 로그 파일 경로
    access_log_file_path = 'C:\\Users\\dsph9\\Desktop\\Access_Log.log'

    # 초기 시그니처 계산 및 저장
    initial_signature = calculate_file_signature(canary_file_path)

    while True: # 무한 루프 

        # 주기적으로 무결성 검사
        if not check_integrity(initial_canary, canary_file_path, log_file_path):
        
            print("무결성이 훼손되었습니다. 파일이 변조되었습니다.")
            restrict_access()
        
            break

        # 카나리 파일 복제 불가 검사
        current_canary_creation_time = get_file_creation_time(canary_file_path)

        if initial_canary_creation_time != current_canary_creation_time:

            print("카나리 파일이 복제되었습니다. 보안 위협이 감지되었습니다.")
            restrict_access()

            break

        # 시그니처 훼손 감지
        if not check_signature_integrity(initial_signature, canary_file_path, log_file_path):
            
            print("시그니처 훼손이 감지되었습니다.")
            restrict_access()
            
            break

        # 파일의 접근 시간 로그 기록
        log_access_time(canary_file_path, access_log_file_path)

        time.sleep(3)  # 3초마다 무결성 검사 수행 (원래는 30초, 60초로 설정하였으나, 파일 변경 시에 검사하는 속도가 늦어 3초로 설정함.)

if __name__ == "__main__":

    main()

