const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// FOR UPLOAD OF DOCUMENTS
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname)));

// ROUTE FOR INDEX.HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Index.html'));
});

// MySQL Database Connection
const db = mysql.createConnection({
    host: 'localhost', 
    user: 'root',     
    password: 'Password@123', 
    database: 'Centralized_KYC' 
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err.message);
        return;
    }
    console.log('Connected to the MySQL database.');
});



// API FOR CUSTOMER LOGIN
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const query = 'SELECT * FROM User_Authentication WHERE email = ? AND role = "Customer"';
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error('Error fetching user:', err.message);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }

        if (results.length === 0) {
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }

        res.json({ message: 'Login successful!' });
    });
});

// API FOR CUSTOMER REGISTRATION
app.post('/api/register', async (req, res) => {
    const { fullName, email, phone, password } = req.body;
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const customerQuery = `
        INSERT INTO Customers (full_name, email, phone_number, date_of_birth, address)
        VALUES (?, ?, ?, '2000-01-01', 'Default Address')
    `;
    db.query(customerQuery, [fullName, email, phone], (err, customerResult) => {
        if (err) {
            console.error('Error inserting customer data:', err.message);
            res.status(500).json({ error: 'Failed to register customer' });
            return;
        }

        const customerId = customerResult.insertId; 

        // INSERTION OF VALUES INTO USER AUTHENTICATION
        const authQuery = `
            INSERT INTO User_Authentication (customer_id, email, password_hash, role, account_status)
            VALUES (?, ?, ?, 'Customer', 'Active')
        `;

        db.query(authQuery, [customerId, email, hashedPassword], (err) => {
            if (err) {
                console.error('Error inserting user authentication data:', err.message);
                res.status(500).json({ error: 'Failed to register user authentication' });
                return;
            }

            res.json({ message: 'Customer registered successfully!' });
        });
    });
});

// API FOR BANK REGISTRATION
app.post('/api/bank/register', async (req, res) => {
    const { bankName, branch, contactEmail, password } = req.body;
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const bankQuery = `
        INSERT INTO Banks (bank_name, branch, contact_email)
        VALUES (?, ?, ?)
    `;
    db.query(bankQuery, [bankName, branch, contactEmail], (err, bankResult) => {
        if (err) {
            console.error('Error inserting bank data:', err.message);
            res.status(500).json({ error: 'Failed to register bank' });
            return;
        }

        const bankId = bankResult.insertId;

        // INSERTION OF VALUES INTO USER AUTHENTICATION
        const authQuery = `
            INSERT INTO User_Authentication (bank_id, email, password_hash, role, account_status)
            VALUES (?, ?, ?, 'Bank_Official', 'Active')
        `;
        db.query(authQuery, [bankId, contactEmail, hashedPassword], (err) => {
            if (err) {
                console.error('Error inserting user authentication data:', err.message);
                res.status(500).json({ error: 'Failed to register user authentication' });
                return;
            }
            res.json({ message: 'Bank registered successfully!' });
        });
    });
});

// API FOR BANK LOGIN
app.post('/api/bank/login', (req, res) => {
    const { email, password } = req.body;
    const query = 'SELECT * FROM User_Authentication WHERE email = ? AND role = "Bank_Official"';
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error('Error fetching user:', err.message);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }

        if (results.length === 0) {
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }

        const user = results[0];

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }

        res.json({ message: 'Login successful!' });
    });
});

// API FOR ADMIN LOGIN
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;
    const query = 'SELECT * FROM User_Authentication WHERE email = ? AND role = "Admin"';
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error('Error fetching user:', err.message);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }

        if (results.length === 0) {
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }

        res.json({ message: 'Login successful!' });
    });
});

// API FOR ADMIN REGISTRATION
app.post('/api/admin/register', async (req, res) => {
    const { email, password } = req.body;
    const checkQuery = 'SELECT * FROM User_Authentication WHERE role = "Admin"';
    db.query(checkQuery, (err, results) => {
        if (err) {
            console.error('Error checking for existing admin:', err.message);
            res.status(500).json({ error: 'Internal server error' });
            return;
        }

        if (results.length > 0) {
            res.status(400).json({ error: 'An admin already exists' });
            return;
        }
        const saltRounds = 10;
        bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
            if (err) {
                console.error('Error hashing password:', err.message);
                res.status(500).json({ error: 'Internal server error' });
                return;
            }

 //  INSERTION OF VALUES INTO USER AUTHENTICATION
            const insertQuery = `
                INSERT INTO User_Authentication (email, password_hash, role, account_status)
                VALUES (?, ?, 'Admin', 'Active')
            `;
            db.query(insertQuery, [email, hashedPassword], (err) => {
                if (err) {
                    console.error('Error inserting admin:', err.message);
                    res.status(500).json({ error: 'Failed to register admin' });
                    return;
                }

                res.json({ message: 'Admin registered successfully!' });
            });
        });
    });
});

// API TO FETCH ADMIN LOG 
app.get('/api/audit-logs', (req, res) => {
    const query = `
        SELECT 
            al.log_id,
            al.user_id,
            al.role,
            al.action,
            al.ip_address,
            al.timestamp,
            CASE 
                WHEN al.role = 'Customer' THEN c.full_name
                WHEN al.role = 'Bank_Official' THEN b.bank_name
                ELSE 'Admin'
            END as user_name
        FROM Audit_Logs al
        LEFT JOIN User_Authentication ua ON al.user_id = ua.user_id
        LEFT JOIN Customers c ON ua.customer_id = c.customer_id
        LEFT JOIN Banks b ON ua.bank_id = b.bank_id
        ORDER BY al.timestamp DESC
        LIMIT 1000
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching audit logs:', err.message);
            res.status(500).json({ error: 'Failed to fetch audit logs' });
            return;
        }
        results = results.map(log => ({
            ...log,
            user_id: log.user_name || log.user_id
        }));
        res.json(results);
    });
});

// API FOR VERIFICATION REQUESTS
app.get('/api/verification-requests', (req, res) => {
    const query = `
        SELECT 
            vr.request_id, 
            c.full_name AS customer_name, 
            kyc.document_type, 
            vr.request_date, 
            COALESCE(a.status, 'Pending') AS status,
            a.verified_by,
            a.verification_date
        FROM Verification_Requests vr
        JOIN Customers c ON vr.customer_id = c.customer_id
        JOIN KYC_Documents kyc ON vr.document_id = kyc.document_id
        LEFT JOIN Approval_Status a ON vr.request_id = a.request_id
        ORDER BY vr.request_date DESC
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching verification requests:', err.message);
            res.status(500).json({ error: 'Failed to fetch verification requests' });
            return;
        }
        res.json(results);
    });
});

// API FOR FETCHING CUSTOMER DATA
app.get('/api/customers', async (req, res) => {
    try {
        const [customers] = await db.promise().query(`
            SELECT 
                c.customer_id,
                c.full_name,
                c.email,
                c.phone_number
            FROM Customers c
            ORDER BY c.full_name ASC
        `);

        const [documents] = await db.promise().query(`
            SELECT 
                kd.customer_id,
                kd.document_id,
                kd.document_type,
                kd.verification_status,
                vr.request_id
            FROM KYC_Documents kd
            LEFT JOIN Verification_Requests vr ON kd.document_id = vr.document_id
            LEFT JOIN Approval_Status a ON vr.request_id = a.request_id
        `);

        const customerData = customers.map(customer => ({
            ...customer,
            documents: documents.filter(doc => doc.customer_id === customer.customer_id)
        }));

        res.json(customerData);
    } catch (error) {
        console.error('Error fetching customers:', error);
        res.status(500).json({ error: 'Failed to fetch customers' });
    }
});

//API FOR BANK INFORMATION
app.get('/api/banks', (req, res) => {
    const query = `
        SELECT 
            bank_id, 
            bank_name, 
            branch, 
            contact_email, 
            registered_at 
        FROM Banks
        ORDER BY bank_name ASC
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching banks:', err);
            return res.status(500).json({ error: 'Failed to fetch banks' });
        }
        res.json(results);
    });
});

// API FOR KYC DOCUMENTS
app.get('/api/kyc-documents', (req, res) => {
    const customerId = 1; // Replace with dynamic customer ID
    const query = `
        SELECT 
            kd.document_id, 
            kd.document_type, 
            kd.document_number, 
            kd.upload_date, 
            kd.file_path, 
            COALESCE(vr.verification_status, 'Not Applied') AS verification_status
        FROM KYC_Documents kd
        LEFT JOIN (
            SELECT 
                vr.document_id, 
                a.status AS verification_status
            FROM Verification_Requests vr
            LEFT JOIN Approval_Status a ON vr.request_id = a.request_id
        ) vr ON kd.document_id = vr.document_id
        WHERE kd.customer_id = ?
        ORDER BY kd.upload_date DESC
    `;

    db.query(query, [customerId], (err, results) => {
        if (err) {
            console.error('Error fetching documents:', err);
            return res.status(500).json({ error: 'Failed to fetch documents' });
        }
        res.json(results);
    });
});

// API TO FETCH VERIFICATION REQUESTS
app.get('/api/verification-requests', (req, res) => {
    const query = `
        SELECT 
            vr.request_id, 
            c.full_name AS customer_name, 
            kyc.document_type, 
            vr.request_date, 
            a.status AS verification_status
        FROM Verification_Requests vr
        JOIN Customers c ON vr.customer_id = c.customer_id
        JOIN KYC_Documents kyc ON vr.customer_id = kyc.customer_id
        LEFT JOIN Approval_Status a ON vr.request_id = a.request_id
        ORDER BY vr.request_date DESC
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching verification requests:', err.message);
            res.status(500).json({ error: 'Failed to fetch verification requests' });
            return;
        }

        res.json(results);
    });
});

// API TO FETCH APPROVAL STATUS
app.get('/api/approval-status', (req, res) => {
    const query = `
        SELECT 
            a.request_id, 
            vr.request_date, 
            a.status, 
            a.verified_by, 
            a.verification_date
        FROM Approval_Status a
        JOIN Verification_Requests vr ON a.request_id = vr.request_id
        ORDER BY a.verification_date DESC
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching approval status data:', err.message);
            res.status(500).json({ error: 'Failed to fetch approval status data' });
            return;
        }

        res.json(results);
    });
});


app.post('/api/verification-requests', async (req, res) => {
    const { documentId } = req.body;
    const customerId = 1; // Replace with dynamic customer ID

    try {
        await db.promise().beginTransaction();

        // Check if a verification request already exists
        const [existingRequest] = await db.promise().query(
            'SELECT * FROM Verification_Requests WHERE document_id = ? AND customer_id = ?',
            [documentId, customerId]
        );

        if (existingRequest.length > 0) {
            return res.status(400).json({ error: 'Verification request already exists' });
        }

        // Update document status to Pending
        await db.promise().query(
            'UPDATE KYC_Documents SET verification_status = "Pending" WHERE document_id = ?',
            [documentId]
        );

        // Insert a new verification request
        const [result] = await db.promise().query(
            'INSERT INTO Verification_Requests (customer_id, document_id, request_date) VALUES (?, ?, NOW())',
            [customerId, documentId]
        );

        // Insert a pending approval status for the request
        await db.promise().query(
            'INSERT INTO Approval_Status (request_id, status) VALUES (?, "Pending")',
            [result.insertId]
        );

        await db.promise().commit();
        res.json({ message: 'Verification request applied successfully' });
    } catch (error) {
        await db.promise().rollback();
        console.error('Error applying for verification:', error);
        res.status(500).json({ error: 'Failed to apply for verification' });
    }
});
// API FOR BANK DELECTION
app.delete('/api/banks/:id', (req, res) => {
    const { id } = req.params;

    const checkQuery = `
        SELECT 
            (SELECT COUNT(*) FROM Verification_Requests WHERE bank_id = ?) as verification_count,
            (SELECT COUNT(*) FROM Consent_Management WHERE bank_id = ?) as consent_count
    `;

    db.query(checkQuery, [id, id], (err, results) => {
        if (err) {
            console.error('Error checking bank associations:', err.message);
            res.status(500).json({ error: 'Failed to check bank associations' });
            return;
        }

        const { verification_count, consent_count } = results[0];
        if (verification_count > 0 || consent_count > 0) {
            res.status(400).json({ 
                error: 'Cannot remove bank with existing verification requests or consents' 
            });
            return;
        }
        const deleteAuthQuery = 'DELETE FROM User_Authentication WHERE bank_id = ?';
        db.query(deleteAuthQuery, [id], (err) => {
            if (err) {
                console.error('Error deleting bank authentication:', err.message);
                res.status(500).json({ error: 'Failed to remove bank authentication' });
                return;
            }

            const deleteBankQuery = 'DELETE FROM Banks WHERE bank_id = ?';
            db.query(deleteBankQuery, [id], (err, result) => {
                if (err) {
                    console.error('Error deleting bank:', err.message);
                    res.status(500).json({ error: 'Failed to remove bank' });
                    return;
                }

                if (result.affectedRows === 0) {
                    res.status(404).json({ error: 'Bank not found' });
                    return;
                }
                const auditQuery = `
                    INSERT INTO Audit_Logs (action, user_id, role, ip_address)
                    VALUES (?, 'ADMIN', 'Admin', ?)
                `;
                const action = `Removed bank ID: ${id}`;
                const ipAddress = req.ip;

                db.query(auditQuery, [action, ipAddress], (err) => {
                    if (err) {
                        console.error('Error creating audit log:', err.message);
                    }
                });

                res.json({ message: 'Bank removed successfully' });
            });
        });
    });
});
// API FOR KYC DOCUMENTS CRUD
app.delete('/api/kyc-documents/:id', async (req, res) => {
    const { id } = req.params;

    try {
        await db.promise().beginTransaction();
        const [doc] = await db.promise().query(
            'SELECT file_path, customer_id FROM KYC_Documents WHERE document_id = ?',
            [id]
        );

        if (doc.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }
        await db.promise().query(
            `DELETE FROM Approval_Status 
             WHERE request_id IN (
                SELECT request_id FROM Verification_Requests WHERE document_id = ?
             )`,
            [id]
        );

        await db.promise().query(
            'DELETE FROM Verification_Requests WHERE document_id = ?',
            [id]
        );
        await db.promise().query(
            'DELETE FROM consent_requests WHERE document_id = ?',
            [id]
        );
        await db.promise().query(
            'DELETE FROM KYC_Documents WHERE document_id = ?',
            [id]
        );
        const filePath = path.join(uploadDir, doc[0].file_path);
        fs.unlink(filePath, (err) => {
            if (err) console.error('Error deleting file:', err);
        });

        await db.promise().commit();
        res.json({ message: 'Document deleted successfully' });

    } catch (error) {
        await db.promise().rollback();
        console.error('Error deleting document:', error);
        res.status(500).json({ error: 'Failed to delete document' });
    }
});
async function checkAdminAccess(userId) {
    if (!userId) return false;

    try {
        const [rows] = await db.promise().query(
            'SELECT role FROM User_Authentication WHERE user_id = ? AND role = "Admin"',
            [userId]
        );
        return rows.length > 0;
    } catch (error) {
        console.error('Error checking admin access:', error);
        return false;
    }
}
app.post('/api/consent-requests', (req, res) => {
    const { customerId, documentId, bankId } = req.body;

    if (!customerId || !documentId || !bankId) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const query = `
        INSERT INTO consent_requests (customer_id, document_id, bank_id, status, request_date)
        VALUES (?, ?, ?, 'Pending', NOW())
    `;

    db.query(query, [customerId, documentId, bankId], (err, result) => {
        if (err) {
            console.error('Error creating consent request:', err);
            return res.status(500).json({ error: 'Failed to create consent request' });
        }

        res.status(201).json({ message: 'Consent request created successfully', requestId: result.insertId });
    });
});

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Only PDF, JPEG, and PNG files are allowed'));
        }
        cb(null, true);
    }
});
app.post('/api/kyc-documents', upload.single('documentFile'), async (req, res) => {
    const customerId = 1; 
    const { documentType, documentNumber } = req.body;

    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    try {
        await db.promise().beginTransaction();

        // Find existing doc of this type for this customer
        const [existingDocs] = await db.promise().query(
            'SELECT document_id, file_path FROM KYC_Documents WHERE customer_id = ? AND document_type = ?',
            [customerId, documentType]
        );
        if (existingDocs.length > 0) {
            const oldDocId = existingDocs[0].document_id;
            const oldFilePath = path.join(uploadDir, existingDocs[0].file_path);

            // Delete Approval_Status for this doc
            await db.promise().query(
                `DELETE FROM Approval_Status 
                 WHERE request_id IN (
                    SELECT request_id FROM Verification_Requests WHERE document_id = ?
                 )`,
                [oldDocId]
            );
            // Delete Verification_Requests for this doc
            await db.promise().query(
                'DELETE FROM Verification_Requests WHERE document_id = ?',
                [oldDocId]
            );
            // Delete the old document
            await db.promise().query(
                'DELETE FROM KYC_Documents WHERE document_id = ?',
                [oldDocId]
            );
            // Remove the old file
            if (fs.existsSync(oldFilePath)) {
                fs.unlinkSync(oldFilePath);
            }
        }

        // Insert new document with status 'Pending'
        const insertQuery = `
            INSERT INTO KYC_Documents (
                customer_id, 
                document_type, 
                document_number, 
                file_path,
                verification_status
            ) VALUES (?, ?, ?, ?, 'Pending')
        `;

        await db.promise().query(insertQuery, [
            customerId,
            documentType,
            documentNumber,
            req.file.filename
        ]);

        await db.promise().commit();
        res.json({ message: 'Document uploaded successfully. Please apply for verification.' });

    } catch (error) {
        await db.promise().rollback();
        const filePath = path.join(uploadDir, req.file.filename);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
        console.error('Error uploading document:', error);
        res.status(500).json({ error: 'Failed to upload document' });
    }
});
async function loadBanks() {
    try {
        const response = await fetch('/api/banks/available');
        if (!response.ok) throw new Error('Failed to fetch banks');
        
        const banks = await response.json();
        const bankSelect = document.getElementById('bankSelect');
        bankSelect.innerHTML = '<option value="">Select a bank...</option>';
        
        banks.forEach(bank => {
            bankSelect.innerHTML += `
                <option value="${bank.bank_id}">
                    ${bank.bank_name}${bank.branch ? ` - ${bank.branch}` : ''}
                </option>
            `;
        });
    } catch (error) {
        console.error('Error loading banks:', error);
        alert('Failed to load available banks');
    }
}
app.get('/api/banks/available', (req, res) => {
    const query = `
        SELECT b.bank_id, b.bank_name, b.branch
        FROM Banks b
        JOIN User_Authentication ua ON b.bank_id = ua.bank_id
        WHERE ua.role = 'Bank_Official' 
        AND ua.account_status = 'Active'
        ORDER BY b.bank_name, b.branch
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching banks:', err);
            return res.status(500).json({ error: 'Failed to fetch banks' });
        }
        res.json(results);
    });
});

app.get('/api/approved-documents', async (req, res) => {
    try {
        res.setHeader('Content-Type', 'application/json');

        const [results] = await db.promise().query(`
            SELECT 
                kd.document_id,
                kd.document_type,
                c.customer_id,
                c.full_name as customer_name,
                kd.verification_status
            FROM KYC_Documents kd
            JOIN Customers c ON kd.customer_id = c.customer_id
            WHERE kd.verification_status = 'Approved'
            ORDER BY c.full_name, kd.document_type
        `);
        res.status(200).json(results || []);
    } catch (error) {
        console.error('Error fetching approved documents:', error);
        res.status(500).json({ error: 'Failed to fetch approved documents' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
app.use((err, req, res, next) => {
    console.error('Unhandled Error:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
});

app.put('/api/consent-requests/:requestId', async (req, res) => {
    const { requestId } = req.params;
    const { status } = req.body;

    if (!['Approved', 'Rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    try {
        const [result] = await db.promise().query(
            'UPDATE consent_requests SET status = ? WHERE request_id = ?',
            [status, requestId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Consent request not found' });
        }

        res.json({ message: `Consent request ${status.toLowerCase()} successfully` });
    } catch (error) {
        console.error('Error updating consent request:', error);
        res.status(500).json({ error: 'Failed to update consent request' });
    }
});

// CONSENT REQUEST API
app.get('/api/consent-requests/customer/:customerId', async (req, res) => {
    const { customerId } = req.params;

    try {
        const [requests] = await db.promise().query(
            `SELECT 
                cr.request_id, 
                cr.bank_name, 
                cr.status, 
                cr.request_date
             FROM consent_requests cr
             WHERE cr.customer_id = ?
             ORDER BY cr.request_date DESC`,
            [customerId]
        );

        res.json(requests);
    } catch (error) {
        console.error('Error fetching consent requests:', error);
        res.status(500).json({ error: 'Failed to fetch consent requests' });
    }
});

app.get('/api/consent-requests', async (req, res) => {
    try {
        const [results] = await db.promise().query(`
            SELECT 
                cr.request_id,
                c.full_name AS customer_name,
                kd.document_type,
                cr.request_date,
                cr.status AS consent_status
            FROM consent_requests cr
            LEFT JOIN Customers c ON cr.customer_id = c.customer_id
            LEFT JOIN KYC_Documents kd ON cr.document_id = kd.document_id
            ORDER BY cr.request_date DESC
        `);

        res.json(results);
    } catch (error) {
        console.error('Error fetching consent requests:', error);
        res.status(500).json({ error: 'Failed to fetch consent requests' });
    }
});

app.get('/api/consent-requests/stats', async (req, res) => {
    try {
        const [results] = await db.promise().query(`
            SELECT 
                status AS consent_status, 
                COUNT(*) AS count
            FROM consent_requests
            GROUP BY status
        `);

        const stats = results.reduce((acc, row) => {
            acc[row.consent_status] = row.count;
            return acc;
        }, { Granted: 0, Revoked: 0, Pending: 0 });

        res.json(stats);
    } catch (error) {
        console.error('Error fetching consent request stats:', error);
        res.status(500).json({ error: 'Failed to fetch consent request stats' });
    }
});

function viewDocument(filePath) {
    if (!filePath || filePath === 'undefined') {
        alert('Document file not found');
        return;
    }
    window.open(`/uploads/${filePath}`, '_blank');
}

app.put('/api/verification-requests/:requestId/status', async (req, res) => {
    const { requestId } = req.params;
    const { status } = req.body;

    if (!requestId || requestId === 'null') {
        return res.status(400).json({ error: 'Invalid request ID' });
    }

    if (!['Approved', 'Rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    try {
        // Get document_id for this request
        const [[request]] = await db.promise().query(
            'SELECT document_id FROM Verification_Requests WHERE request_id = ?',
            [requestId]
        );
        if (!request) return res.status(404).json({ error: 'Verification request not found' });

        // Update Approval_Status
        await db.promise().query(
            `UPDATE Approval_Status 
             SET status = ?, verified_by = 'Admin', verification_date = NOW()
             WHERE request_id = ?`,
            [status, requestId]
        );

        // Update KYC_Documents status
        await db.promise().query(
            'UPDATE KYC_Documents SET verification_status = ? WHERE document_id = ?',
            [status, request.document_id]
        );

        res.json({ message: `Verification request ${status.toLowerCase()} successfully` });
    } catch (error) {
        console.error('Error updating verification request status:', error);
        res.status(500).json({ error: 'Failed to update verification request status' });
    }
});

app.get('/api/all-kyc-documents', (req, res) => {
    const customerId = 1; // Replace with dynamic customer ID
    const query = `
        SELECT 
            document_id, 
            document_type, 
            document_number, 
            upload_date, 
            file_path, 
            verification_status
        FROM KYC_Documents
        WHERE customer_id = ?
        ORDER BY upload_date DESC
    `;

    db.query(query, [customerId], (err, results) => {
        if (err) {
            console.error('Error fetching all KYC documents:', err);
            return res.status(500).json({ error: 'Failed to fetch all KYC documents' });
        }
        res.json(results);
    });
});