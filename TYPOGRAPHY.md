# Book Typography Configuration

This project uses a custom AsciiDoctor PDF theme that implements Palatino-style typography as specified.

## Font Specifications Implemented

| Element | Font Size | Font Family | Notes |
|---------|-----------|-------------|-------|
| Chapter Name | 40pt | Palatino-style Serif | Bold, used for book title |
| Chapter Number | 35pt | Palatino-style Serif | Bold |
| H1 | 20pt | Palatino-style Serif | Bold |
| H2 | 18pt | Palatino-style Serif | Bold |
| H3 | 16pt | Palatino-style Serif | Bold |
| Content | 11pt | Palatino-style Serif | Regular weight |
| Figure/Table Caption | 9pt | Palatino-style Serif | Italic |
| Code Block | 10pt | Monospace | M+ 1mn font |
| Line Spacing | 1.15 | | Applied throughout |

## Font Implementation

Since TeX Gyre Pagella (the open-source Palatino clone) had compatibility issues with AsciiDoctor PDF's font rendering engine, we're using **Noto Serif** as the primary font family. Noto Serif provides:

- Excellent readability and professional appearance
- Complete compatibility with AsciiDoctor PDF
- Similar character proportions to Palatino
- Full support for bold, italic, and bold-italic variants
- Extensive Unicode character support

## Files

- `themes/pagella-theme.yml` - Custom AsciiDoctor PDF theme with typography specifications
- `book.adoc` - Main book file with theme configuration
- `build` - Build script that generates the PDF
- `install-fonts.sh` - Font installation script (optional, for system font setup)

## Building the Book

```bash
./build
```

This will generate `book.pdf` with all the specified typography settings.

## Theme Configuration

The theme is configured in `book.adoc` with these attributes:

```adoc
:pdf-theme: pagella
:pdf-themesdir: themes
```

## Customization

To modify the typography:

1. Edit `themes/pagella-theme.yml`
2. Adjust font sizes, spacing, or styling
3. Run `./build` to regenerate the PDF

## Font Fallbacks

If you want to try using the actual TeX Gyre Pagella fonts, you can:

1. Install them: `sudo apt install fonts-texgyre`
2. Modify the theme file to use system font paths
3. Handle any compatibility issues with OpenType fonts

The current configuration prioritizes reliability and professional appearance over using the exact Palatino font.
