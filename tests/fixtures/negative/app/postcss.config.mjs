import tailwindcss from '@tailwindcss/postcss'
import postcssPresetEnv from 'postcss-preset-env'
import utopiaClamp from './postcss/utopia-clamp.mjs'

const config = {
  plugins: [
    tailwindcss(),
    utopiaClamp(),
    postcssPresetEnv({
      autoprefixer: { flexbox: 'no-2009' },
      stage: 3,
      features: {
        'nesting-rules': true,
        'custom-media-queries': true,
        'custom-properties': false,
      },
    }),
  ],
}

export default config;
