const multer = require('multer');
const sharp = require('sharp');
const path = require('path');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');

// Configure storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, '../../uploads/temp'));
    },
    filename: (req, file, cb) => {
        const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

// Configure upload middleware
const upload = multer({
    storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    }
});

// Image processing service
class ImageService {
    constructor() {
        this.uploadsDir = path.join(__dirname, '../../uploads');
        this.tempDir = path.join(this.uploadsDir, 'temp');
        this.processedDir = path.join(this.uploadsDir, 'processed');
        this.thumbnailsDir = path.join(this.uploadsDir, 'thumbnails');
        
        // Ensure directories exist
        this.initDirectories();
    }

    async initDirectories() {
        const dirs = [this.uploadsDir, this.tempDir, this.processedDir, this.thumbnailsDir];
        for (const dir of dirs) {
            try {
                await fs.access(dir);
            } catch {
                await fs.mkdir(dir, { recursive: true });
            }
        }
    }

    async processImage(file, options = {}) {
        const {
            width = 800,
            height = 800,
            quality = 80,
            generateThumbnail = true
        } = options;

        const filename = path.basename(file.filename);
        const processedPath = path.join(this.processedDir, filename);
        const thumbnailPath = path.join(this.thumbnailsDir, filename);

        try {
            // Process main image
            await sharp(file.path)
                .resize(width, height, {
                    fit: 'inside',
                    withoutEnlargement: true
                })
                .jpeg({ quality })
                .toFile(processedPath);

            // Generate thumbnail if requested
            if (generateThumbnail) {
                await sharp(file.path)
                    .resize(200, 200, {
                        fit: 'cover'
                    })
                    .jpeg({ quality: 70 })
                    .toFile(thumbnailPath);
            }

            // Clean up temp file
            await fs.unlink(file.path);

            return {
                filename,
                processedUrl: `/uploads/processed/${filename}`,
                thumbnailUrl: generateThumbnail ? `/uploads/thumbnails/${filename}` : null
            };
        } catch (error) {
            console.error('Image processing error:', error);
            throw new Error('Failed to process image');
        }
    }

    async deleteImage(filename) {
        try {
            const files = [
                path.join(this.processedDir, filename),
                path.join(this.thumbnailsDir, filename)
            ];

            await Promise.all(files.map(file => 
                fs.unlink(file).catch(() => {})
            ));
        } catch (error) {
            console.error('Error deleting image:', error);
            throw new Error('Failed to delete image');
        }
    }

    getUploadMiddleware() {
        return upload.single('image');
    }
}

module.exports = new ImageService(); 