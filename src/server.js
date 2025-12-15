import dotenv from 'dotenv';
import { app } from './app.js';

dotenv.config();
const PORT = process.env.PORT || 3002;

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Server is running on http://localhost:${PORT}`);
});
