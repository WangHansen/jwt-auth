export const mockLoadFromFile = jest
  .fn()
  .mockImplementation(() => Promise.resolve());

export const mockSaveToFile = jest
  .fn()
  .mockImplementation(() => Promise.resolve());

export const mockLoadKeys = jest
  .fn()
  .mockImplementation(() => Promise.resolve());

export const mockLoadClients = jest
  .fn()
  .mockImplementation(() => Promise.resolve());

export const mockLoadRevocationList = jest
  .fn()
  .mockImplementation(() => Promise.resolve());

export const mockSaveKeys = jest
  .fn()
  .mockImplementation(() => Promise.resolve());

export const mockSaveClients = jest
  .fn()
  .mockImplementation(() => Promise.resolve());

export const mockSaveRevocationList = jest
  .fn()
  .mockImplementation(() => Promise.resolve());

const mock = jest.fn().mockImplementation(() => {
  return {
    loadKeys: mockLoadKeys,
    saveKeys: mockSaveKeys,
    loadClients: mockLoadClients,
    saveClients: mockSaveClients,
    loadRevocationList: mockLoadRevocationList,
    saveRevocationList: mockSaveRevocationList,
  };
});

export default mock;
