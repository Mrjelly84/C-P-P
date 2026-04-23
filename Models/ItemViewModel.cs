using System.Collections.ObjectModel;
using AssetGuard.Models;
using AssetGuard.Services;

namespace AssetGuard.ViewModels
{
    public class ItemViewModel
    {
        private readonly ItemRepository _repository;
        private readonly LogService _logService;

        public ObservableCollection<Item> Items { get; } = new();
        public string NewItemText { get; set; } = string.Empty;
        public Item? SelectedItem { get; set; }

        public ItemViewModel(ItemRepository repository, LogService logService)
        {
            _repository = repository;
            _logService = logService;
        }

        public virtual void AddItem()
        {
            if (!string.IsNullOrWhiteSpace(NewItemText))
            {
                _repository.AddItem(NewItemText);
                _logService.LogAction($"User added item: '{NewItemText}'");
                NewItemText = string.Empty;
                RefreshItems();
            }
        }

        public  virtual void RemoveItem()
        {
            if (SelectedItem != null)
            {
                _repository.RemoveItem(SelectedItem.Id);
                _logService.LogAction($"User removed item: '{SelectedItem.Detail}'");
                SelectedItem = null;
                RefreshItems();
            }
        }

        public virtual void RefreshItems()
        {
            var list = _repository.LoadItems();
            Items.Clear();
            foreach (var item in list) Items.Add(item);
        }
    }
}