// Zweiter Beispielbaum: die Familie Ibn Chaldun (بنو خلدون), Tunis und Kairo,
// 13.–15. Jahrhundert. Belegt sind die maennliche Linie und die Brueder; Mutter,
// Ehefrau und die meisten Kinder sind namentlich nicht ueberliefert. Diese
// Luecken bleiben sichtbar — sie sind der ehrliche Fall in echter Genealogie.

const P = [
  // id, given, surname, sex, birth, death, birthPlace, occupation
  ['k_khaldun', 'خلدون', 'بن عثمان', 'M', 'قبل 1200', 'ca. 1250', 'إشبيلية', 'جدّ الأسرة، هاجر من الأندلس'],
  ['k_hasan', 'الحسن', 'بن خلدون', 'M', 'ca. 1250', 'ca. 1310', 'تونس', 'من وجهاء الدولة الحفصية'],
  ['k_muhammad_h', 'محمد', 'بن الحسن بن خلدون', 'M', 'ca. 1280', '1337', 'تونس', 'كاتب في الديوان الحفصي'],
  ['k_muhammad', 'محمد', 'بن محمد بن خلدون', 'M', 'ca. 1305', '1349', 'تونس', 'فقيه وأديب، توفي في الطاعون الأسود'],
  ['k_mother', '', 'بنت الأسرة الحفصية', 'F', '', 'ca. 1349', '', ''],
  ['k_ibn', 'عبد الرحمن', 'بن خلدون', 'M', '27.05.1332', '17.03.1406', 'تونس', 'مؤرخ وقاضٍ، صاحب المقدمة'],
  ['k_yahya', 'يحيى', 'بن خلدون', 'M', '1333', '1379', 'تونس', 'مؤرخ وكاتب، قُتل في تلمسان'],
  ['k_muhammad_b', 'محمد', 'بن خلدون', 'M', 'ca. 1336', '', 'تونس', ''],
  ['k_wife', '', 'بنت محمد بن الحكيم', 'F', 'ca. 1340', '1384', 'تونس', ''],
  ['k_son', 'محمد', 'بن عبد الرحمن بن خلدون', 'M', 'ca. 1365', 'بعد 1406', 'بجاية', 'كاتب'],
  ['k_daughter1', '', 'بنت عبد الرحمن', 'F', 'ca. 1368', '1384', 'تونس', ''],
  ['k_daughter2', '', 'بنت عبد الرحمن', 'F', 'ca. 1371', '1384', 'تونس', ''],
  ['k_daughter3', '', 'بنت عبد الرحمن', 'F', 'ca. 1374', 'بعد 1406', 'القاهرة', ''],
  ['k_grandson', 'عبد الرحمن', 'بن محمد', 'M', 'ca. 1395', '', 'القاهرة', '']
];

const F = [
  // id, spouses, children, marriage year, place
  ['fk_khaldun', ['k_khaldun'], ['k_hasan'], '', 'إشبيلية'],
  ['fk_hasan', ['k_hasan'], ['k_muhammad_h'], '', 'تونس'],
  ['fk_muhammad_h', ['k_muhammad_h'], ['k_muhammad'], '', 'تونس'],
  ['fk_muhammad', ['k_muhammad', 'k_mother'], ['k_ibn', 'k_yahya', 'k_muhammad_b'], 'ca. 1330', 'تونس'],
  ['fk_ibn', ['k_ibn', 'k_wife'], ['k_son', 'k_daughter1', 'k_daughter2', 'k_daughter3'], 'ca. 1362', 'بسكرة'],
  ['fk_son', ['k_son'], ['k_grandson'], '', 'القاهرة']
];

export function khaldunOps() {
  const ops = [];
  for (const [id, given, surname, sex, birth, death, birthPlace, occupation] of P) {
    ops.push({
      type: 'upsertPerson',
      id,
      fields: {
        given, surname, sex, birth, death, birthPlace,
        deathPlace: id === 'k_ibn' ? 'القاهرة' : '',
        custom: occupation ? { occupation } : {},
        sources: id === 'k_ibn' ? [
          { title: 'التعريف بابن خلدون ورحلته غربًا وشرقًا', detail: 'سيرة ذاتية', supports: 'biography' },
          { title: 'كتاب العبر', detail: 'الجزء السابع', supports: 'birth' },
          { title: 'الضوء اللامع للسخاوي', detail: '806 هـ', supports: 'death' }
        ] : [],
        note: id === 'k_ibn'
          ? 'وُلد في تونس ونشأ فيها، ثم عمل كاتبًا وسفيرًا لدى حكّام المغرب والأندلس. ألّف المقدمة سنة 1377 في قلعة ابن سلامة، وانتقل إلى القاهرة سنة 1382 حيث تولّى قضاء المالكية ودرّس في الأزهر. غرقت أسرته في طريقها إليه سنة 1384.'
          : id === 'k_yahya'
            ? 'مؤرخ الدولة الزيانية وصاحب «بغية الرواد»، قُتل في تلمسان سنة 1379.'
            : ''
      }
    });
  }
  for (const [id, spouses, children, marriage, place] of F) {
    ops.push({ type: 'upsertFamily', id, fields: { spouses, children, facts: { marriage, place } } });
  }
  return ops;
}

export const KHALDUN_FOCUS = 'k_ibn';
export const KHALDUN_COUNT = P.length;
