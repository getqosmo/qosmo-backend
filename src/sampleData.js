// Offline fallback dataset. Used when the TCG API is unreachable, rate-limited,
// or when USE_SAMPLE_DATA=true. Numbers are illustrative but realistically
// shaped so generated content reads like genuine market analysis.

const SAMPLES = {
  pokemon: [
    { name: 'Charizard (Base Set, Holo)', set: 'Base Set', number: '4/102', rarity: 'Holo Rare', grade: 'PSA 9', price: 4200, priceChange24h: 3.1, priceChange7d: 8.4, priceChange30d: 12.0, volume: 38 },
    { name: 'Umbreon VMAX (Alt Art)', set: 'Evolving Skies', number: '215/203', rarity: 'Secret Rare', grade: 'PSA 10', price: 1180, priceChange24h: 14.2, priceChange7d: 19.6, priceChange30d: 31.5, volume: 142 },
    { name: 'Pikachu Illustrator', set: 'Promo', number: '—', rarity: 'Promo', grade: 'PSA 7', price: 286000, priceChange24h: -1.2, priceChange7d: 2.0, priceChange30d: -4.5, volume: 2 },
    { name: 'Lugia (Neo Genesis, Holo)', set: 'Neo Genesis', number: '9/111', rarity: 'Holo Rare', grade: 'PSA 8', price: 940, priceChange24h: -11.8, priceChange7d: -6.1, priceChange30d: 3.2, volume: 21 },
    { name: 'Moonbreon Singles (raw)', set: 'Evolving Skies', number: '215/203', rarity: 'Secret Rare', grade: 'raw', price: 410, priceChange24h: 0.4, priceChange7d: 1.1, priceChange30d: 9.0, volume: 510 },
  ],
  magic: [
    { name: 'Black Lotus (Alpha)', set: 'Alpha', number: '—', rarity: 'Rare', grade: 'BGS 9', price: 540000, priceChange24h: 0.6, priceChange7d: 1.8, priceChange30d: 5.0, volume: 1 },
    { name: 'Ragavan, Nimble Pilferer', set: 'MH2', number: '138', rarity: 'Mythic', grade: 'raw', price: 42, priceChange24h: -8.7, priceChange7d: -12.3, priceChange30d: -18.0, volume: 880 },
    { name: 'The One Ring (Serialized)', set: 'LOTR', number: '001/001', rarity: 'Special', grade: 'raw', price: 2100000, priceChange24h: 0, priceChange7d: 0, priceChange30d: 0, volume: 0 },
    { name: 'Sheoldred, the Apocalypse', set: 'DMU', number: '107', rarity: 'Mythic', grade: 'raw', price: 78, priceChange24h: 12.9, priceChange7d: 16.4, priceChange30d: 22.1, volume: 640 },
    { name: 'Mox Sapphire (Beta)', set: 'Beta', number: '—', rarity: 'Rare', grade: 'PSA 8', price: 16800, priceChange24h: 2.2, priceChange7d: -3.0, priceChange30d: 4.4, volume: 6 },
  ],
  sports: [
    { name: 'Michael Jordan Fleer Rookie', set: '1986 Fleer', number: '57', rarity: 'Base RC', grade: 'PSA 10', price: 285000, priceChange24h: -2.0, priceChange7d: 4.5, priceChange30d: 9.8, volume: 4 },
    { name: 'Victor Wembanyama Prizm Silver', set: '2023 Prizm', number: '136', rarity: 'Silver RC', grade: 'PSA 10', price: 1650, priceChange24h: 18.5, priceChange7d: 24.0, priceChange30d: 41.2, volume: 230 },
    { name: 'Tom Brady Bowman Chrome RC', set: '2000 Bowman', number: '236', rarity: 'Base RC', grade: 'BGS 9.5', price: 12500, priceChange24h: -14.3, priceChange7d: -9.0, priceChange30d: -2.1, volume: 18 },
    { name: 'Luka Doncic Prizm Silver RC', set: '2018 Prizm', number: '280', rarity: 'Silver RC', grade: 'PSA 10', price: 3200, priceChange24h: 5.6, priceChange7d: -2.4, priceChange30d: 6.0, volume: 95 },
    { name: 'Shohei Ohtani Bowman Chrome Auto', set: '2018 Bowman', number: 'BCP-OHT', rarity: 'Auto RC', grade: 'BGS 9', price: 5400, priceChange24h: 0.9, priceChange7d: 7.2, priceChange30d: 15.5, volume: 60 },
  ],
};

export function sampleCards(category) {
  const rows = SAMPLES[category] || SAMPLES.sports;
  return rows.map((row, i) => ({
    id: `${category}-sample-${i}`,
    game: category,
    ...row,
  }));
}
