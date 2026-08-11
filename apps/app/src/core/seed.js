// Fixture: die Bach-Familie, gross genug damit Graph, Fächer und die
// "+X"-Knoten realistisch greifen (~60 Personen, 6 Generationen).
// Format: kompakte Tabellen, daraus werden Ops erzeugt.

const P = [
  // id, given, surname, sex, birth, death, birthPlace, occupation
  ['p_veit', 'Veit', 'Bach', 'M', 'ca. 1550', '1619', 'Wechmar', 'Bäcker, Cymbal-Spieler'],
  ['p_annav', 'Anna', 'Bach', 'F', 'ca. 1555', 'ca. 1615', '', ''],
  ['p_hans', 'Johannes', 'Bach', 'M', '1580', '1626', 'Wechmar', 'Spielmann'],
  ['p_annas', 'Anna', 'Schmied', 'F', 'ca. 1585', '1635', 'Wechmar', ''],
  ['p_joh1604', 'Johann', 'Bach', 'M', '1604', '1673', 'Wechmar', 'Organist in Erfurt'],
  ['p_christoph', 'Christoph', 'Bach', 'M', '1613', '1661', 'Wechmar', 'Hofmusiker in Weimar'],
  ['p_heinrich', 'Heinrich', 'Bach', 'M', '1615', '1692', 'Wechmar', 'Organist in Arnstadt'],
  ['p_grabler', 'Maria Magdalena', 'Grabler', 'F', 'ca. 1614', '1661', 'Prettin', ''],
  ['p_georgchr', 'Georg Christoph', 'Bach', 'M', '1642', '1697', 'Erfurt', 'Kantor in Schweinfurt'],
  ['p_ambrosius', 'Johann Ambrosius', 'Bach', 'M', '1645', '1695', 'Erfurt', 'Stadtpfeifer in Eisenach'],
  ['p_jchr1645', 'Johann Christoph', 'Bach', 'M', '1645', '1693', 'Erfurt', 'Hofmusiker in Arnstadt'],
  ['p_valentin', 'Valentin', 'Lämmerhirt', 'M', '1608', '1665', 'Erfurt', 'Kürschner'],
  ['p_hedwig', 'Hedwig', 'Lämmerhirt', 'F', 'ca. 1610', '1666', 'Erfurt', ''],
  ['p_elisabeth', 'Maria Elisabeth', 'Lämmerhirt', 'F', '1644', '1694', 'Erfurt', ''],
  ['p_katharina', 'Katharina', 'Lämmerhirt', 'F', 'ca. 1647', 'vor 1700', 'Erfurt', ''],
  ['p_jchr1671', 'Johann Christoph', 'Bach', 'M', '1671', '1721', 'Eisenach', 'Organist in Ohrdruf'],
  ['p_balthasar', 'Johann Balthasar', 'Bach', 'M', '1673', '1691', 'Eisenach', ''],
  ['p_jonas', 'Johann Jonas', 'Bach', 'M', '1675', '1685', 'Eisenach', ''],
  ['p_salome', 'Maria Salome', 'Bach', 'F', '1677', '1727', 'Eisenach', ''],
  ['p_juditha', 'Johanna Juditha', 'Bach', 'F', '1680', '1686', 'Eisenach', ''],
  ['p_jacob', 'Johann Jacob', 'Bach', 'M', '1682', '1722', 'Eisenach', 'Hofoboist in Stockholm'],
  ['p_jsb', 'Johann Sebastian', 'Bach', 'M', '21.03.1685', '28.07.1750', 'Eisenach', 'Thomaskantor in Leipzig'],
  ['p_michael', 'Johann Michael', 'Bach', 'M', '1648', '1694', 'Arnstadt', 'Organist in Gehren'],
  ['p_wedemann', 'Catharina', 'Wedemann', 'F', 'ca. 1651', '1704', 'Arnstadt', ''],
  ['p_barbara', 'Maria Barbara', 'Bach', 'F', '1684', '1720', 'Gehren', ''],
  ['p_friedelena', 'Friedelena Margaretha', 'Bach', 'F', '1675', '1729', 'Gehren', ''],
  ['p_caspar', 'Johann Caspar', 'Wilcke', 'M', '1660', '1733', 'Zeitz', 'Hoftrompeter'],
  ['p_liebe', 'Margaretha Elisabeth', 'Liebe', 'F', 'ca. 1665', '1746', 'Zeitz', ''],
  ['p_magdalena', 'Anna Magdalena', 'Wilcke', 'F', '1701', '1760', 'Zeitz', 'Sängerin'],
  ['p_dorothea', 'Catharina Dorothea', 'Bach', 'F', '1708', '1774', 'Weimar', ''],
  ['p_wf', 'Wilhelm Friedemann', 'Bach', 'M', '1710', '1784', 'Weimar', 'Organist in Halle'],
  ['p_twin1', 'Johann Christoph', 'Bach', 'M', '1713', '1713', 'Weimar', ''],
  ['p_twin2', 'Maria Sophia', 'Bach', 'F', '1713', '1713', 'Weimar', ''],
  ['p_cpe', 'Carl Philipp Emanuel', 'Bach', 'M', '1714', '1788', 'Weimar', 'Musikdirektor in Hamburg'],
  ['p_bernhard', 'Johann Gottfried Bernhard', 'Bach', 'M', '1715', '1739', 'Weimar', 'Organist in Mühlhausen'],
  ['p_leopold', 'Leopold Augustus', 'Bach', 'M', '1718', '1719', 'Köthen', ''],
  ['p_sophia', 'Christiana Sophia', 'Bach', 'F', '1723', '1726', 'Köthen', ''],
  ['p_gottfriedh', 'Gottfried Heinrich', 'Bach', 'M', '1724', '1763', 'Leipzig', ''],
  ['p_gottlieb', 'Christian Gottlieb', 'Bach', 'M', '1725', '1728', 'Leipzig', ''],
  ['p_juliane', 'Elisabeth Juliane Friederica', 'Bach', 'F', '1726', '1781', 'Leipzig', ''],
  ['p_ernestus', 'Ernestus Andreas', 'Bach', 'M', '1727', '1727', 'Leipzig', ''],
  ['p_reginaj', 'Regina Johanna', 'Bach', 'F', '1728', '1733', 'Leipzig', ''],
  ['p_benedicta', 'Christiana Benedicta', 'Bach', 'F', '1730', '1730', 'Leipzig', ''],
  ['p_christianad', 'Christiana Dorothea', 'Bach', 'F', '1731', '1732', 'Leipzig', ''],
  ['p_jcf', 'Johann Christoph Friedrich', 'Bach', 'M', '1732', '1795', 'Leipzig', 'Konzertmeister in Bückeburg'],
  ['p_augustabr', 'Johann August Abraham', 'Bach', 'M', '1733', '1733', 'Leipzig', ''],
  ['p_jc', 'Johann Christian', 'Bach', 'M', '1735', '1782', 'Leipzig', 'Komponist in London'],
  ['p_carolina', 'Johanna Carolina', 'Bach', 'F', '1737', '1781', 'Leipzig', ''],
  ['p_susanna', 'Regina Susanna', 'Bach', 'F', '1742', '1809', 'Leipzig', ''],
  ['p_georgi', 'Dorothea Elisabeth', 'Georgi', 'F', 'ca. 1721', '1791', 'Halle', ''],
  ['p_friederica', 'Friederica Sophia', 'Bach', 'F', '1757', 'nach 1800', 'Halle', ''],
  ['p_dannemann', 'Johanna Maria', 'Dannemann', 'F', 'ca. 1724', '1795', 'Berlin', ''],
  ['p_augustcpe', 'Johann August', 'Bach', 'M', '1745', '1789', 'Berlin', 'Jurist'],
  ['p_annacar', 'Anna Carolina Philippina', 'Bach', 'F', '1747', '1804', 'Berlin', ''],
  ['p_jsbmaler', 'Johann Sebastian', 'Bach', 'M', '1748', '1778', 'Berlin', 'Maler'],
  ['p_cecilia', 'Cecilia', 'Grassi', 'F', 'ca. 1746', '1782', 'Neapel', 'Sängerin'],
  ['p_lucia', 'Lucia Elisabeth', 'Münchhausen', 'F', 'ca. 1750', '1803', 'Bückeburg', 'Sängerin'],
  ['p_wfe', 'Wilhelm Friedrich Ernst', 'Bach', 'M', '1759', '1845', 'Bückeburg', 'Cembalist'],
  ['p_anna1728', 'Anna Philippina', 'Bach', 'F', 'vor 1730', '', 'Erfurt', '']
];

const F = [
  // id, spouses, children, marriage year, place
  ['f_veit', ['p_veit', 'p_annav'], ['p_hans'], 'ca. 1575', 'Wechmar'],
  ['f_hans', ['p_hans', 'p_annas'], ['p_joh1604', 'p_christoph', 'p_heinrich'], '1602', 'Wechmar'],
  ['f_christoph', ['p_christoph', 'p_grabler'], ['p_georgchr', 'p_ambrosius', 'p_jchr1645'], '1642', 'Erfurt'],
  ['f_laemmer', ['p_valentin', 'p_hedwig'], ['p_elisabeth', 'p_katharina'], '1640', 'Erfurt'],
  ['f_ambrosius', ['p_ambrosius', 'p_elisabeth'], ['p_jchr1671', 'p_balthasar', 'p_jonas', 'p_salome', 'p_juditha', 'p_jacob', 'p_jsb'], '1668', 'Erfurt'],
  ['f_michael', ['p_michael', 'p_wedemann'], ['p_barbara', 'p_friedelena'], '1675', 'Arnstadt'],
  ['f_wilcke', ['p_caspar', 'p_liebe'], ['p_magdalena'], 'ca. 1690', 'Zeitz'],
  ['f_jsb1', ['p_jsb', 'p_barbara'], ['p_dorothea', 'p_wf', 'p_twin1', 'p_twin2', 'p_cpe', 'p_bernhard', 'p_leopold'], '17.10.1707', 'Dornheim'],
  ['f_jsb2', ['p_jsb', 'p_magdalena'], ['p_sophia', 'p_gottfriedh', 'p_gottlieb', 'p_juliane', 'p_ernestus', 'p_reginaj', 'p_benedicta', 'p_christianad', 'p_jcf', 'p_augustabr', 'p_jc', 'p_carolina', 'p_susanna'], '03.12.1721', 'Köthen'],
  ['f_wf', ['p_wf', 'p_georgi'], ['p_friederica'], '1751', 'Halle'],
  ['f_cpe', ['p_cpe', 'p_dannemann'], ['p_augustcpe', 'p_annacar', 'p_jsbmaler'], '1744', 'Berlin'],
  ['f_jc', ['p_jc', 'p_cecilia'], [], '1773', 'London'],
  ['f_jcf', ['p_jcf', 'p_lucia'], ['p_wfe'], '1755', 'Bückeburg'],
  ['f_joh1604', ['p_joh1604'], ['p_anna1728'], '', 'Erfurt']
];

export function seedOps() {
  const ops = [];
  for (const [id, given, surname, sex, birth, death, birthPlace, occupation] of P) {
    ops.push({
      type: 'upsertPerson',
      id,
      fields: {
        given, surname, sex, birth, death, birthPlace,
        deathPlace: '',
        custom: occupation ? { occupation } : {},
        sources: id === 'p_jsb' ? [
          { title: 'Taufregister St. Georg Eisenach', detail: '1685, fol. 42', supports: 'birth' },
          { title: 'Traueintrag Dornheim', detail: '1707', supports: 'marriage' },
          { title: 'Bach-Dokumente II, Nr. 441', detail: '1750', supports: 'death' },
          { title: 'Nekrolog 1754', detail: 'Mizler', supports: 'biography' }
        ] : [],
        note: id === 'p_jsb'
          ? 'Organist in Arnstadt und Mühlhausen, Hofmusiker in Weimar und Köthen, ab 1723 Thomaskantor in Leipzig. Mit zehn Jahren Waise, aufgezogen vom älteren Bruder Johann Christoph in Ohrdruf.'
          : ''
      }
    });
  }
  for (const [id, spouses, children, marriage, place] of F) {
    ops.push({
      type: 'upsertFamily',
      id,
      fields: { spouses, children, facts: { marriage, place } }
    });
  }
  return ops;
}

export const SEED_FOCUS = 'p_jsb';
export const SEED_COUNT = P.length;
