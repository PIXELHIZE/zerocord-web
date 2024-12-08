const API_URL = 'http://localhost:3000';

async function fetchWithCredentials(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        credentials: 'include',
        headers: {
            ...options.headers,
            'Content-Type': 'application/json',
        },
    });

    if (!response.ok) {
        // 텍스트로 오류 내용을 읽기
        const errorText = await response.text();

        try {
            // JSON으로 파싱 시도
            const errorJson = JSON.parse(errorText);
            // JSON 내 에러 메시지 추출 후 예쁘게 포맷팅
            const formattedError = errorJson.error || "An unknown error occurred.";
            throw new Error(formattedError);
        } catch {
            // JSON 파싱 실패 시 원본 텍스트 사용
            const fallbackError = errorText || "An unknown error occurred.";
            throw new Error(fallbackError);
        }
    }

    return response.json();
}

// 로그인
export async function login(username, password, csrfToken) {
	return fetchWithCredentials(`${API_URL}/login`, {
		method: 'POST',
		headers: {
			'X-CSRF-Token': csrfToken,
		},
		body: JSON.stringify({ username, password }),
	});
}

// 로그아웃
export async function logout() {
	return fetchWithCredentials(`${API_URL}/logout`, {
		method: 'POST',
	});
}

// 기록 업로드
export async function uploadRecord(record, csrfToken) {
	const formData = new FormData();
	for (const [key, value] of Object.entries(record)) {
	  formData.append(key, value);
	}
  
	const response = await fetch(`${API_URL}/upload`, {
	  method: 'POST',
	  body: formData,
	  headers: {
		'X-CSRF-Token': csrfToken
	  },
	  credentials: 'include'
	});
	if (!response.ok) throw new Error('Failed to upload record');
	return response.json();
}
  

export async function downloadFile(fileKey) {
	// Explicitly use the backend server URL (API_URL)
	const url = `localhost:3000/files/${encodeURIComponent(fileKey)}`;
	console.log('Requesting file from URL:', url); // Debugging log
  
	try {
	  const response = await fetch(url, { 
		method: 'GET', 
		credentials: 'include', 
	  });
  
	  if (!response.ok) {
		console.error('Failed to download file:', response.status, response.statusText);
		throw new Error(`Failed to download file: ${response.statusText}`);
	  }
  
	  const blob = await response.blob();
	  const downloadUrl = window.URL.createObjectURL(blob);
	  const a = document.createElement('a');
	  a.style.display = 'none';
	  a.href = downloadUrl;
	  
	  // Safely extract the filename, handling different path formats
	  const filename = fileKey.split(/[/\\]/).pop() || 'downloaded-file';
	  a.download = filename;
	  
	  document.body.appendChild(a);
	  a.click();
	  
	  // Clean up
	  document.body.removeChild(a);
	  window.URL.revokeObjectURL(downloadUrl);
	} catch (error) {
	  console.error('Download error:', error);
	  throw error;
	}
  }
  
  

export async function deleteRecord(id, csrfToken) {
	const response = await fetch(`${API_URL}/records/${id}`, {
	  method: 'DELETE',
	  headers: {
		'X-CSRF-Token': csrfToken
	  },
	  credentials: 'include'
	});
	if (!response.ok) throw new Error('Failed to delete record');
	return response.json();
}

// 기록 불러오기
export async function getRecords() {
	const response = await fetch(`${API_URL}/records`, {
	  credentials: 'include'
	});
	if (!response.ok) throw new Error('Failed to fetch records');
	return response.json();
}

export async function getRecordDetails(id) {
	const response = await fetch(`${API_URL}/records/${id}`, {
	  credentials: 'include'
	});
	if (!response.ok) throw new Error('Failed to fetch record details');
	return response.json();
}

// 로그인 여부 확인
export async function checkAuth() {
	try {
		const response = await fetchWithCredentials(`${API_URL}/check-auth`);
		return response.isLoggedIn;
	} catch (error) {
		return false;
	}
}

// CSRF 토큰 가져오기
export async function getCsrfToken() {
	const response = await fetch(`${API_URL}/csrf-token`, {
	  credentials: 'include'
	});
	if (!response.ok) throw new Error('Failed to get CSRF token');
	const data = await response.json();
	return data.csrfToken;
}

// 기록 검색
export async function searchRecords(searchParams) {
	const queryString = new URLSearchParams(searchParams).toString();
	const response = await fetch(`${API_URL}/search?${queryString}`, {
	  credentials: 'include'
	});
	if (!response.ok) throw new Error('Failed to search records');
	return response.json();
}
  

// 사용자 권한 가져오기
export async function getUserPermission() {
	const response = await fetch(`${API_URL}/user-permission`, {
	  credentials: 'include'
	});
	if (!response.ok) throw new Error('Failed to get user permission');
	return response.json();
}

// 새 계정 생성
export async function createAccount(account) {
	return fetchWithCredentials(`${API_URL}/admin/create-account`, {
		method: 'POST',
		body: JSON.stringify(account),
	});
}

// 모든 계정 목록 불러오기
export async function getAccounts() {
	return fetchWithCredentials(`${API_URL}/admin/accounts`);
}

// 계정 삭제
export async function deleteAccount(username) {
	return fetchWithCredentials(`${API_URL}/admin/delete-account`, {
		method: 'POST',
		body: JSON.stringify({ username }),
	});
}

// 비밀번호 초기화
export async function resetPassword(username, newPassword) {
	return fetchWithCredentials(`${API_URL}/admin/reset-password`, {
		method: 'POST',
		body: JSON.stringify({ username, newPassword }),
	});
}

// 계정 권한 수정
export async function updateAccountPermission(username, permission) {
	return fetchWithCredentials(`${API_URL}/admin/update-permission`, {
		method: 'POST',
		body: JSON.stringify({ username, permission }),
	});
}
