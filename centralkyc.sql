CREATE DATABASE Centralized_KYC;
USE Centralized_KYC;

CREATE TABLE Customers (
    customer_id INT PRIMARY KEY AUTO_INCREMENT,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone_number VARCHAR(15) UNIQUE NOT NULL,
    date_of_birth DATE NOT NULL,
    address TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
select * from customers;

CREATE TABLE Banks (
    bank_id INT PRIMARY KEY AUTO_INCREMENT,
    bank_name VARCHAR(100) NOT NULL,
    branch VARCHAR(100),
    contact_email VARCHAR(100) UNIQUE NOT NULL,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
select * from banks;
CREATE TABLE KYC_Documents (
    document_id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id INT,
    document_type ENUM('Aadhar', 'PAN', 'Passport', 'Voter ID') NOT NULL,
    document_number VARCHAR(50) UNIQUE NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES Customers(customer_id) ON DELETE CASCADE
);
select * from kyc_documents;
ALTER TABLE KYC_Documents ADD COLUMN file_path VARCHAR(255) NOT NULL;
ALTER TABLE KYC_Documents 
ADD COLUMN verification_status ENUM('Pending', 'Approved', 'Rejected') 
DEFAULT 'Pending';

CREATE TABLE Verification_Requests (
    request_id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id INT,
    bank_id INT,
    request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES Customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (bank_id) REFERENCES Banks(bank_id) ON DELETE CASCADE
);
select * from verification_requests;
ALTER TABLE Verification_Requests 
ADD COLUMN document_id INT,
ADD FOREIGN KEY (document_id) REFERENCES KYC_Documents(document_id);
CREATE TABLE Approval_Status (
    request_id INT PRIMARY KEY,
    status ENUM('Pending', 'Approved', 'Rejected') NOT NULL,
    verified_by VARCHAR(100),
    verification_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES Verification_Requests(request_id) ON DELETE CASCADE
);
select * from approval_status;

CREATE TABLE Consent_Management (
    consent_id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id INT,
    bank_id INT,
    consent_status ENUM('Granted', 'Revoked') NOT NULL,
    consent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES Customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (bank_id) REFERENCES Banks(bank_id) ON DELETE CASCADE
);
ALTER TABLE Consent_Management 
ADD COLUMN document_id INT,
ADD COLUMN expiry_date TIMESTAMP,
ADD FOREIGN KEY (document_id) REFERENCES KYC_Documents(document_id);

-- Update consent_status enum to include Pending
ALTER TABLE Consent_Management 
MODIFY COLUMN consent_status ENUM('Pending', 'Granted', 'Revoked') NOT NULL;
ALTER TABLE consent_requests ADD COLUMN document_id INT;
ALTER TABLE consent_requests ADD FOREIGN KEY (document_id) REFERENCES KYC_Documents(document_id);
ALTER TABLE Consent_Management 
ADD COLUMN request_id INT,
ADD FOREIGN KEY (request_id) REFERENCES consent_requests(request_id),
ADD FOREIGN KEY (document_id) REFERENCES KYC_Documents(document_id);
select * from consent_management;


CREATE TABLE User_Authentication (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id INT NULL,
    bank_id INT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Customer', 'Bank_Official', 'Admin') NOT NULL,
    account_status ENUM('Active', 'Suspended', 'Deactivated') DEFAULT 'Active',
    last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES Customers(customer_id) ON DELETE SET NULL,
    FOREIGN KEY (bank_id) REFERENCES Banks(bank_id) ON DELETE SET NULL
);
select * from user_authentication;
CREATE TABLE consent_requests (
    request_id INT AUTO_INCREMENT PRIMARY KEY,
    request_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    status ENUM('Pending', 'Approved', 'Rejected') DEFAULT 'Pending'
);
select * from consent_requests;
ALTER TABLE consent_requests
ADD COLUMN bank_id INT,
ADD FOREIGN KEY (bank_id) REFERENCES Banks(bank_id);

ALTER TABLE consent_requests 
ADD COLUMN customer_id INT,
ADD FOREIGN KEY (customer_id) REFERENCES Customers(customer_id);

CREATE TABLE Audit_Logs (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    role ENUM('Customer', 'Bank_Official', 'Admin') NOT NULL,
    action VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES User_Authentication(user_id) ON DELETE CASCADE
);
select * from audit_logs;

