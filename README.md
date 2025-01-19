사이버 공격자들은 지속적인 공격을 통해 장시간 공격 대상 시스템에 머물며 정보 탈취나 시스템 파괴 등의 공격을 목적으로 한다.     
하지만 최근에는 네트워크 기반 보안 솔루션 이외에도 다층 기술 스택의 보안 강화를 위해 엔드포인트의 보안 강화가 활발하다.      
엔드포인트 보안을 위한 기본 솔루션인 백신 프로그램 이외에도 EDR, XDR 등을 통해 파일리스 공격이나 스크립트 기반의 악성 행위를 탐지하여 피해 최소화를 위해 노력하고 있다.     
특히 공격자들은 단일 악성코드 공격으로 인한 탐지율을 낮추기 위해 LotL(Living off the Land)을 활용해 공격 대상에 설치되어 있는 PowerShell이나 WMI 등을 활용하는 비중이 높아지고 있다.     

공격자들의 공격패턴이 변화하는 가장 큰 이유는 탐지 최소화를 위해서다.      
DLL을 활용한 공격 역시 공격 페이로드가 포함된 DLL을 활용하면 공격 흔적을 최소화할 수 있기 때문에 공격자들이 즐겨 사용하는 방식이다.   
DLL을 활용한 공격은 크게 정상적인 프로세스의 메모리상에 직접적으로 악성 공격코드를 주입하는 인젝션(Injection)과 하이재킹(Hijacking)이 있다.      

Injection 공격에는 DLL Injection, Process Hollowing, PE Injection, Threat Injection, Reflective DLL Injection, API Injection 등이 존재하는데 이 중 가장 유명한 공격이 DLL Injection이다.     
정상적인 프로세스의 메모리상에서 직접적으로 악성 DLL을 강제로 삽입(Injection)하는 공격방식이다.     

Hijacking은 공격자가 공격에 사용될 DLL 파일 내부에 악성코드를 삽입한 이후 DLL 파일을 검색하고 로드하는 방식을 악용하여 애플리케이션에 악성코드를 주입하는 방식을 DLL 하이재킹(DLL Hijacking)이라 한다.    
Windows 2000이 출시된 이후 널리 사용된 공격방식으로 DLL 파일이 사용되는 Windows 운영체제에서만 사용할 수 있다.     
DLL Hijacking에서 가장 빈번하게 사용되는 공격은 Search Order Hijacking이다.      
정상적인 실행파일을 이용하는 경우가 많기 때문에 일반적으로 탐지하기 어려울 뿐만 아니라 의심스러운 실행파일을 완전히 차단하는 경우     
사용자가 사용 중인 PC에 심각한 문제를 일으킬 수 있기 때문에 Search Order Hijacking을 많이 사용한다.    
  
본격적으로 DLL을 활용한 공격기법을 살펴보기에 앞서 DLL의 개념과 기존 사이버 공격에서 DLL이 사용되거나 악용되는 공격방식에 관해서 설명할 예정이다.         
![image](https://github.com/user-attachments/assets/eb2c78b6-53db-4365-b963-3d37334e0e4f)
1) Rundll32를 이용한 공격방식

Rundll32는 기본 Windows 프로세스 및 필수 구성 요소로 시스템을 손상시키지 않고는 차단하거나 비활성화할 수 없다.       
공격자들은 일반적으로 악성 활동과 정상적인 작업을 구분하기 어렵게 만들기 때문에 Rundll32를 악용하며, 자격 증명 도용 및 실행 우회 수단으로 Rundll32를 활용한다.       

실용적인 관점에서 볼 때, Rundll32는 동적 링크 라이브러리(DLL)를 실행할 수 있게 해준다.       
악성 코드를 DLL로 실행하는 것은 실행 파일로 악성 코드를 실행하는 방식에 비해서 상대적으로 탐지가 잘되지 않는다.     
DLL 로드를 차단하기 위한 제어 기능이 없는 경우 Rundll32를 통한 악성 코드 실행은 백신을 비롯한 보안 솔루션을 우회할 수 있다.      

Rundll32를 악용하여 공격하는 방식으로 크게 4가지가 있다.    

1) 보안 솔루션을 우회하기 위해 정상적인 함수를 사용        
2) 정상적인 DLL 또는 import 함수를 악용하여 악성 행위 수행        
3) 공격자가 피해자 장비에 다운로드 한 DLL 실행       
4) 정상적인 DLL의 이름을 바꾸거나 재배치하여 악의적인 목적으로 사용         

사용방식도 간단하며 DLL 경로와 악성코드를 돌릴 DLL 진입점만 필요하다. 또한, 윈도우의 실행을 포함하여 cmd, Powershell에서 동일하게 동작하기 때문에 스크립트 기반에서도 동작이 가능하다.        
![image](https://github.com/user-attachments/assets/ff5fac61-e63f-4797-a6b2-e96d6f02e4e9)          
대표적으로 rundll32.exe을 악용하여 사용이 가능한 도구로 mimikatz가 있다.           
Windows 환경에서 자격증명 정보를 수집하는 도구로 모의 침투 테스트 도구이자 공격자가 정보 탈취에 사용할 수 있는 도구이기도 하다.      
Windows 서비스인 Lsass.exe에 저장된 인증정보를 덤프 파일(.dmp)로 저장한 이후 mimikatz 실행 시 자격증명 정보를 확보할 수 있다.      

여기서 정상적인 DLL 파일인 comsvcs.dll 내 MiniDumpW 함수를 이용하여 덤프 파일 생성이 가능한 점을 이용하여 lsass.exe의 덤프 파일을 손쉽게 생성할 수 있다.       
![image](https://github.com/user-attachments/assets/f1b6f458-b44a-4193-afb9-0e3998f5140d)

2) Injection을 이용한 공격방식

① DLL Injection

DLL Injection은 실행 중인 다른 프로세스의 공간에 강제로 DLL을 Injection 하는 방법을 의미한다.              
비교적 간단한 방법으로 DLL을 Injection 시킬 수 있기 때문에 악성코드에서 많이 사용되었으나 CreateRemoteThread로 대상 프로세스의 Injection 된 DLL을 실행할 때 들어가는 lpStartAddress 인자 때문에 쉽게 탐지된다는 단점을 가진다.     
lpStartAddress 인자에는 GetProcAddress를 통해 얻어온 LoadLibrary(혹은 GetProcAddress) API의 주소가 들어가게 되는데 이 부분을 탐지하게 되면 DLL Injection을 막을 수 있게 된다.          

② Reflective DLL Injection

Reflective DLL Injection은 기존의 DLL Injection 방법과 달리 현재 실행 중인 프로세스의 메모리에 임의의 DLL에 대한 데이터를 삽입한 후 직접 매핑(Mapping) 하여 실행시키는 방법으로 동작한다.              
이러한 동작 방법으로 실제 악성 행위를 하는 DLL은 백그라운드에 존재하지 않으며 탐지 또한 어렵다. 이러한 점에서 파일리스(Fileless) 악성코드에서 많이 사용되고 있으며 2017년 이슈가 되었던 SMB 취약점 이터널블루(Eternal Blue)와 더블펄서(Double Pulsar)에서도 사용되었다.              
   

![image](https://github.com/user-attachments/assets/1e2ff35d-a880-4689-a089-5124d0689c93)       

3) Hijacking을 이용한 공격방식    

DLL Hijacking은 방어 회피(Defense Evasion), 지속성(Persistence) 및 권한 상승(Privilege Escalation)을 목적으로 악성 코드를 로드 하는 데 사용되는 기법이다.           
공격자는 실행 파일을 통해 직접 악성 코드를 실행하는 대신 합법적인 애플리케이션을 활용하여 악성 DLL 파일을 로드한다. 이 기법을 사용하면 악성 코드가 애플리케이션 허용 목록이나 백신 탐지 등을 우회할 수 있다.      
Process Explorer로 실행 중인 프로세스를 확인할 경우 정상적인 애플리케이션이 실행 중인 것으로만 보이기 때문에 탐지가 어렵다.

DLL Hijacking을 크게 4가지 공격 기법으로 나눌 수 있으며 ① ~ ④으로 간략하게 정리하였다. 현재 공격에 가장 많이 사용되고 있는 ① Search Order Hijacking은 다음 챕터에서 상세하게 다룰 예정이다.         

① Search Order Hijacking

가장 잘 알려진 DLL Hijacking 예시인 Search Order Hijacking은 공격자가 Windows 운영 체제에서 DLL 검색에 사용되는 검색 방식을 악용하여 합법적인 프로세스에서 악성 코드를 실행하도록 속이는 경우이다.         

② Relative path DLL hijacking

Search Order Hijacking의 변종으로 공격자가 적절한 쓰기 권한이 있는 폴더에 악성 DLL과 함께 합법적인 실행 파일의 이름을 변경하여 생성하는 경우로 notepad.exe가 불러오는 DLL 정보를 미리 확보한 이후    
notepad.exe가 위치한 경로가 아닌 전혀 다른 경로에 옮긴 이후 파일명 변경과 악성 DLL을 같은 폴더에 두고 실행하는 방식이다.                 
         
③ Phantom DLL hijacking

Windows 운영 체제는 존재하지 않는 DLL 파일을 의외로 많이 참조하는 것을 이용하여 공격자가 이러한 누락된 DLL 중 하나를 지정하여 악성 DLL을 작성하는 공격 방식으로 운영 체제에서 해당 파일을 참조하는 코드를 실행할 때 이 DLL이 로드된다.                  

한 가지 예시로 IKEEXT 서비스는 Windows 시작 시 실행되며 인터넷 프로토콜 보안에서 인증 및 키 교환에 사용된다. 시작 시 IKEEXT는 C:\Windows\System32\wlbsctrl.dll 파일을 로드하려고 시도하지만, 이 DLL은 존재하지 않는다. 공격자가 해당 경로 또는 지정된 경로에 공격자가 원하는 악성 DLL 파일을 생성할 수 있는 경우, IKEEXT 서비스가 시작/재시작될 때 악성 코드가 실행될 수 있다.         

④ DLL redirection

DLL Hijacking에서 가장 새로운 방법의 하나로 공격자는 미리 정의된 검색 순서를 활용하는 대신 운영 체제가 DLL 파일을 검색하는 위치를 변경한다. 예를 들어, 공격자는 레지스트리를 변경하여 검색 순서를 수정하고 프로그램이 다른 DLL 파일을 실행하도록 조작이 가능하다.

예를 들면 MSDTC 서비스에서 사용되는 C:\windows\system32\oci.dll를 공격자가 원하는 DLL로 변경한 이후 “HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\MTxOCI\OracleOciLib” 레지스트리에 접근하여 OracleOciLib 키를 변경한 DLL의 이름으로 변경한다. 변경 이후 MSDTC 서비스를 재시작하면 악성 DLL 실행이 가능하게 된다.
![image](https://github.com/user-attachments/assets/fcab612b-c0a7-4045-9954-af0932bd2c0a)

03. Search Order Hijacking

Search Order Hijacking은 공격자가 Windows 운영 체제의 잘 문서화된 동작을 악용하여 합법적인 프로세스에서 악성 코드를 실행하도록 속이는 경우이다. Windows 시스템은 프로그램에 로드 할 필수 DLL을 찾는 데 일반적인 방법을 사용한다. 일반적인 순서는 1) ~ 6)으로 구성되며 빠른 순서에서 탐색된 DLL을 먼저 로드한다.      
1) 프로그램이 로드된 디렉토리
2) 시스템 디렉토리 (system32, SysWO64)
3) 16비트 시스템 디렉토리 (거의 사용되지 않음)
4) Windows 디렉토리
5) 현재 디렉토리
6) PATH 환경변수에 설정된 디렉토리

문제는 빠른 순서에서 탐색된 DLL을 먼저 로드하기 때문에 정상 프로그램이 로드해야 할 DLL보다 공격자가 빠른 순서에 삽입한 악성 DLL이 먼저 로드 될 가능성이 존재한다. 이를 이용하여 공격하는 방식이 Search Order Hijacking이며 Process Explorer를 이용하여 로드된 DLL 정보를 확인하기 전까지 정상 프로그램에 부착된 상태로 사용되기 때문에 일반적인 방법으로 확인하기 어렵다.

1) 정상 파일을 이용한 예시

Search Order Hijacking이 실제로 가능한지 알아보기 위해 정상 파일을 이용하여 테스트를 진행하였다.             
사용되는 파일은 Microsoft Windows에서 사용되는 화상 키보드 프로그램으로 실행 시 OskSupport.dll을 로드한다.  \  
기존에 osk.exe 경로에서 실행될 때 DLL 로드 현황과 다른 경로에서 실행될 때의 DLL 로드 현황을 비교하여 실제로 Search Order Hijacking이 가능한지 알아보고자 한다.
 

![image](https://github.com/user-attachments/assets/84d2663c-5da0-4617-8d68-7535eda105ac)
Osk.exe는 Microsoft Windows에서 사용되는 화상 키보드 프로그램으로 C:\Windows\system32에 존재한다. 로드하는 DLL 정보 확인 시 OskSupport.dll에서 API 2개를 로드하며 화상 키보드 관련된 API로 확인된다.

![image](https://github.com/user-attachments/assets/8d99df5c-5992-442e-a090-5691118eb38a)
특별한 조작 없이 화상키보드를 실행 후 로드된 DLL 정보를 확인하기 위해 Process Explorer를 이용하여 확인한 결과 C:\Windows\system32 하위에서 실행되며 OskSupport.dll를 동일한 경로에서 로드하여 정상 실행 중인 것으로 확인된다.

![image](https://github.com/user-attachments/assets/8d95fde6-7313-4987-9d8a-16644e0a5c52)

Osk.exe, OskSupport.dll를 바탕화면에 test 폴더를 생성한 이후 복사하였으며, 동일한 경로에서 osk.exe 실행 시 C:\Windows\system32 하위에 OskSupport.dll을 로드하지 않고 DLL 검색 절차의 1번인 프로그램이 로드된 디렉토리에 존재하는 OskSupport.dll을 로드한다.
![image](https://github.com/user-attachments/assets/dd74e386-d45d-4f3f-9c2e-983fa7ec38a4)

2) Search Order Hijacking를 활용한 악성코드 사례분석

2020년 8월부터 활동 중인 APT 공격 그룹 LuminousMoth는 주로 미얀마, 필리핀, 태국 및 기타 동남아시아 지역의 정부 기관을 목표로 활동 중인 공격 그룹이다.

사례 분석에 사용된 샘플은 미얀마 교통통신부, 대외경제관계부를 대상으로 정보탈취를 목적으로 한 APT 공격에서 사용되었으며, 정상적인 Microsoft Office Word 실행 파일과 Microsoft Silverlight 실행파일을 이용하여 악성코드를 실행하였다.

최초 공격 시작은 스피어피싱을 통해 Dropbox에 업로드한 악성코드를 다운로드하게 하였으며 이번 사례에서는 악성코드 다운로드 이후 해당 악성코드가 어떤 행위를 통해 악성행위를 시작하는지에 대해 알아보고자 한다.

![image](https://github.com/user-attachments/assets/cfd86b12-792c-41d8-8f4e-5c05d29990b7)
![image](https://github.com/user-attachments/assets/77169611-88c0-425b-981f-d38a4a5ebf14)

igfxEM.exe는 정상적인 디지털 서명이 적용되어 있는 파일로 Microsoft Silverlight 관련 실행파일로 확인되며 Import DLL 중 VERSION.dll을 로드하는 것으로 확인된다.

![image](https://github.com/user-attachments/assets/02a7889a-d0bc-43cd-982d-769113cbef1d)
igfxEM.exe 실행에는 assist, system 및 실행 인자 없음의 세 가지 실행 인자가 필요하며 실행 시 입력된 실행 인자에 따라 악성행위를 처리한다.

![image](https://github.com/user-attachments/assets/a0458a6a-d412-43bd-b29b-20852463556f)

실행 인자가 assist인 경우 “nfvlqfnlqwnlf” 이름의 이벤트를 생성하며 동일한 경로에 존재하는 WINWORD.EXE를 실행시킨다.

![image](https://github.com/user-attachments/assets/22317a90-4e49-49fd-87f8-84f17552b93f)
피해자 PC에서 지속성을 얻기 위해 “\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run” 경로에 PC 재시작 시 자기 자신을 assist 실행 인자로 실행하도록 등록한다. 추가적으로 시스템 내 이동식 디스크를 질의하며 목록을 동일한 경로의 udisk.log로 저장한 이후 system 인자로 재시작한다.


![image](https://github.com/user-attachments/assets/a83d6943-9bcc-4cb2-8947-187326faedd9)
실행 인자가 system인 경우 “qjlfqwle21ljl” 이름의 이벤트를 생성하며 이전에 질의한 이동식 디스크에 숨겨진 디렉터리를 생성한다. 이 디렉터리 안에는 WinWord.exe와 wwlib.dll가 위치한다. igfxem.exe 파일을 USB Driver.exe로 변경한 이후 VERSION.dll과 함께 이동식 디스크의 최상위 폴더에 복사한다.

![image](https://github.com/user-attachments/assets/3ccb33e5-bd26-4062-b458-7ea2678a7208)
![image](https://github.com/user-attachments/assets/60bdcd1d-94d5-4997-ba2d-5b84135772e4)

아무런 실행 인자 없이 실행하는 경우는 감염된 USB에서 직접 실행하는 경우로 “C:\Users\Public\Documents\Shared Virtual Machines\” 폴더에 정상파일을 포함한 악성파일 4종을 저장한다.

![image](https://github.com/user-attachments/assets/7e467787-0688-465d-a3b3-cdce5588fe41)
wwlib.dll는 WinWord.exe에서 실행되며 103[.]15[.]28[.]195와 GET 통신 시도하는 것으로 확인된다. 통신 시 다운로드하는 파일은 Gmail 프로필을 이용하여 정상 통신과 혼합하여 통신하는 Cobalt Strike Beacon으로 확인된다.

![image](https://github.com/user-attachments/assets/9554d00c-b52d-4f9f-8736-bdef0550f10e)

05. 참고자료

1) Hijack Execution Flow: DLL Search Order Hijacking
https://attack.mitre.org/techniques/T1574/001/
2) 4 Ways Adversaries Hijack DLLs — and How CrowdStrike Falcon OverWatch Fights Back
https://www.crowdstrike.com/blog/4-ways-adversaries-hijack-dlls/
3) 동적 링크 라이브러리 검색 순서
https://learn.microsoft.com/ko-kr/windows/win32/dlls/dynamic-link-library-search-order
4) The Good, the Bad, and the Web Bug: TA416 Increases Operational Tempo Against European Governments as Conflict in Ukraine Escalates
https://www.proofpoint.com/us/blog/threat-insight/good-bad-and-web-bug-ta416-increases-operational-tempo-against-european
