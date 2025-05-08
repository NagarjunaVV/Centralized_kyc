const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Move these lines to the top, right after initializing the app
const app = express();
const PORT = 3000;

// Serve static files from the uploads directory - must come before other middleware
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Middleware to parse JSON and form data
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (HTML, CSS, JS) from the CENTRALIZED_KYC directory
app.use(express.static(path.join(__dirname)));

// Route to serve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Index.html'));
});

// MySQL Database Connection
const db = mysql.createConnection({
    host: 'localhost', // Replace with your MySQL host
    user: 'root',      // Replace with your MySQL username
    password: 'Password@123', // Replace with your MySQL password
    database: 'Centralized_KYC' // Replace with your database name
});

// Connect to the database
db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err.message);
        return;
    }
    console.log('Connected to the MySQL database.');
});



// API Endpoint to handle customer login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    // Query to find the user by email
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

        // Compare the provided password with the hashed password in the database
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }

        res.json({ message: 'Login successful!' });
    });
});

// API Endpoint to handle customer registration
app.post('/api/register', async (req, res) => {
    const { fullName, email, phone, password } = req.body;

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert customer data into the Customers table
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

        const customerId = customerResult.insertId; // Get the inserted customer ID

        // Insert user authentication data into the User_Authentication table
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

// API Endpoint to handle bank registration
app.post('/api/bank/register', async (req, res) => {
    const { bankName, branch, contactEmail, password } = req.body;

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert bank data into the Banks table
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

        const bankId = bankResult.insertId; // Get the inserted bank ID

        // Insert user authentication data into the User_Authentication table
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

// API Endpoint to handle bank login
app.post('/api/bank/login', (req, res) => {
    const { email, password } = req.body;

    // Query to find the bank user by email
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

        // Compare the provided password with the hashed password in the database
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }

        res.json({ message: 'Login successful!' });
    });
});

// API Endpoint to handle admin login
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;

    // Query to find the admin user by email
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

        // Compare the provided password with the hashed password in the database
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            res.status(401).json({ error: 'Invalid email or password' });
            return;
        }

        res.json({ message: 'Login successful!' });
    });
});

// API Endpoint to register a new admin
app.post('/api/admin/register', async (req, res) => {
    const { email, password } = req.body;

    // Check if an admin already exists
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

        // Hash the password
        const saltRounds = 10;
        bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
            if (err) {
                console.error('Error hashing password:', err.message);
                res.status(500).json({ error: 'Internal server error' });
                return;
            }

            // Insert the new admin into the User_Authentication table
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

// API Endpoint to fetch audit logs
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

// Add with your other endpoints
app.get('/api/verification-requests', (req, res) => {
    const query = `
        SELECT 
            vr.request_id,
            c.full_name AS customer_name,
            kd.document_type,
            vr.request_date,
            COALESCE(a.status, 'Pending') as status
        FROM Verification_Requests vr
        JOIN Customers c ON vr.customer_id = c.customer_id
        JOIN KYC_Documents kd ON vr.customer_id = kd.customer_id
        LEFT JOIN Approval_Status a ON vr.request_id = a.request_id
        ORDER BY 
            CASE WHEN a.status = 'Pending' OR a.status IS NULL THEN 0 ELSE 1 END,
            vr.request_date DESC
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching verification requests:', err);
            return res.status(500).json({ error: 'Failed to fetch verification requests' });
        }
        res.json(results);
    });
});

// API Endpoint to fetch customer data
app.get('/api/customers', async (req, res) => {
    try {
        const [results] = await db.promise().query(`
            SELECT 
                c.customer_id,
                c.full_name,
                c.email,
                c.phone_number,
                COUNT(kd.document_id) AS document_count,
                (
                    SELECT verification_status 
                    FROM KYC_Documents 
                    WHERE customer_id = c.customer_id 
                    ORDER BY upload_date DESC 
                    LIMIT 1
                ) AS latest_status
            FROM Customers c
            LEFT JOIN KYC_Documents kd ON c.customer_id = kd.customer_id
            GROUP BY c.customer_id
            ORDER BY c.full_name ASC
        `);

        res.json(results);
    } catch (error) {
        console.error('Error fetching customers:', error);
        res.status(500).json({ error: 'Failed to fetch customers' });
    }
});

// Keep only this simplified version of the banks endpoint
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

// API Endpoint to fetch KYC documents
app.get('/api/kyc-documents', (req, res) => {
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
            console.error('Error fetching documents:', err);
            return res.status(500).json({ error: 'Failed to fetch documents' });
        }
        res.json(results);
    });
});

// API Endpoint to fetch verification requests
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

// API Endpoint to fetch approval status data
app.get('/api/approval-status', (req, res) => {
    const query = `
        SELECT 
            a.request_id, 
            b.bank_name, 
            vr.request_date, 
            a.status, 
            a.verified_by, 
            a.verification_date
        FROM Approval_Status a
        JOIN Verification_Requests vr ON a.request_id = vr.request_id
        JOIN Banks b ON vr.bank_id = b.bank_id
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

// Update the verification request endpoint
app.post('/api/verification-requests', async (req, res) => {
    const { documentId, bankId } = req.body;
    const customerId = 1; // Replace with actual customer ID from session

    try {
        await db.promise().beginTransaction();

        // Create verification request
        const [result] = await db.promise().query(
            'INSERT INTO Verification_Requests (customer_id, bank_id, document_id, request_date) VALUES (?, ?, ?, NOW())',
            [customerId, bankId, documentId]
        );

        // Create initial approval status
        await db.promise().query(
            'INSERT INTO Approval_Status (request_id, status) VALUES (?, "Pending")',
            [result.insertId]
        );

        await db.promise().commit();
        res.json({ 
            message: 'Verification request created successfully',
            requestId: result.insertId
        });

    } catch (error) {
        await db.promise().rollback();
        console.error('Error creating verification request:', error);
        res.status(500).json({ error: 'Failed to create verification request' });
    }
});

// Add this endpoint after your existing endpoints
app.delete('/api/banks/:id', (req, res) => {
    const { id } = req.params;

    // First check if the bank has any associated records
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

        // If no associations exist, proceed with deletion
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

                // Add to audit log
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

// Update the document deletion endpoint
app.delete('/api/kyc-documents/:id', async (req, res) => {
    const { id } = req.params;

    try {
        await db.promise().beginTransaction();

        // First get document details
        const [doc] = await db.promise().query(
            'SELECT file_path, customer_id FROM KYC_Documents WHERE document_id = ?',
            [id]
        );

        if (doc.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }

        // Delete verification requests and approval status
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

        // Delete consent requests
        await db.promise().query(
            'DELETE FROM consent_requests WHERE document_id = ?',
            [id]
        );

        // Delete document record
        await db.promise().query(
            'DELETE FROM KYC_Documents WHERE document_id = ?',
            [id]
        );

        // Delete physical file
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

// Helper function to check admin access
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

// Add endpoint to request KYC access
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

// Configure multer
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
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Only PDF, JPEG, and PNG files are allowed'));
        }
        cb(null, true);
    }
});

// Update the document upload endpoint
app.post('/api/kyc-documents', upload.single('documentFile'), async (req, res) => {
    const customerId = 1; // Replace with actual customer ID from session
    const { documentType, documentNumber } = req.body;

    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    try {
        await db.promise().beginTransaction();

        // Check if document type already exists for this customer
        const [existingDocs] = await db.promise().query(
            'SELECT document_id, file_path FROM KYC_Documents WHERE customer_id = ? AND document_type = ?',
            [customerId, documentType]
        );

        // If document exists, delete old file and record
        if (existingDocs.length > 0) {
            const oldFilePath = path.join(uploadDir, existingDocs[0].file_path);
            if (fs.existsSync(oldFilePath)) {
                fs.unlinkSync(oldFilePath);
            }

            await db.promise().query(
                'DELETE FROM KYC_Documents WHERE document_id = ?',
                [existingDocs[0].document_id]
            );
        }

        // Insert new document
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
        res.json({ message: 'Document uploaded successfully' });

    } catch (error) {
        await db.promise().rollback();
        // Delete uploaded file if database operation fails
        const filePath = path.join(uploadDir, req.file.filename);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
        console.error('Error uploading document:', error);
        res.status(500).json({ error: 'Failed to upload document' });
    }
});

// Add this function to load banks from database
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

// Update the verification request endpoint in server.js
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

// Update the approved-documents endpoint
app.get('/api/approved-documents', async (req, res) => {
    try {
        // Ensure proper headers are set
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

        // Send JSON response
        res.status(200).json(results || []);
    } catch (error) {
        console.error('Error fetching approved documents:', error);

        // Return a JSON error response
        res.status(500).json({ error: 'Failed to fetch approved documents' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

// Add this middleware at the end of all routes in server.js
app.use((err, req, res, next) => {
    console.error('Unhandled Error:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message });
});

// Update consent request status (approve/reject)
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

// Get all consent requests for a customer (for consent_management.html)
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

// Update verification request status (approve/reject)
app.put('/api/verification-requests/:requestId/status', async (req, res) => {
    const { requestId } = req.params;
    const { status } = req.body;

    if (!['Approved', 'Rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    try {
        const [result] = await db.promise().query(
            `UPDATE Approval_Status 
             SET status = ?, verified_by = 'Bank Official', verification_date = NOW()
             WHERE request_id = ?`,
            [status, requestId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Verification request not found' });
        }

        res.json({ message: `Verification request ${status.toLowerCase()} successfully` });
    } catch (error) {
        console.error('Error updating verification request status:', error);
        res.status(500).json({ error: 'Failed to update verification request status' });
    }
});