import { defineConfig } from 'astro/config';
import rehypeSlug from 'rehype-slug';

export default defineConfig({
  site: 'https://mpaktrust.org',
  build: {
    format: 'directory'
  },
  markdown: {
    rehypePlugins: [rehypeSlug]
  }
});
