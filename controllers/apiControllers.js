export const generateAPIKey = async (req, res) => {
    try {
        
    }
    catch (error) {
        console.error('Error generating API key:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}